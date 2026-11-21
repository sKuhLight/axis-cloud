import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient, type SupabaseClient } from "jsr:@supabase/supabase-js@2";

// Orphan-blob sweep. Quota enforcement is metadata-gated (a preset_versions BEFORE INSERT trigger),
// so an interrupted or rejected sync can leave a blob in Storage with no metadata row referencing
// it. Such blobs are invisible to the app (everything resolves via preset_versions.blob_path) but
// cost storage — this function removes any blob not referenced by a blob_path, skipping objects
// younger than 24 h so it never races an in-flight sync that uploads blob-before-metadata.
//
// It also enforces the retention of diagnostic captures (MT): rows past `expires_at` are deleted together
// with their object in the private `diagnostic-captures` bucket; reservations whose upload was never
// confirmed (`status = 'pending'`) are removed after the same 24 h grace; and objects no row references any
// more (a crashed upload, or leftovers after account deletion cascaded the rows away) are removed after that
// grace too. The result is reported under `diagnostics`.
//
// NOT user-facing: gated by a shared secret header (GC_SECRET env), meant for manual invocation or
// a schedule (pg_cron / dashboard scheduled trigger; recommended: once a day). Pass ?dry=1 to report
// without deleting.
const GRACE_MS = 24 * 60 * 60 * 1000;

const DIAG_BUCKET = "diagnostic-captures";
// Bounds one run per category (rows are removed oldest-first; the remainder is picked up by the next run).
const DIAG_MAX_PER_RUN = 5000;

type Admin = SupabaseClient;

interface DiagnosticsSweep {
  expiredRows: number;
  stalePendingRows: number;
  objectsRemoved: number;
  rowsRemoved: number;
  orphanObjects: number;
  orphanObjectsRemoved: number;
  error?: string;
}

/** Every entry directly under `prefix` (folders have a null id), paged — storage `list` caps a page. */
async function listEntries(admin: Admin, bucket: string, prefix: string) {
  const out: { name: string; id: string | null; created_at: string | null }[] = [];
  for (let offset = 0; ; offset += 1000) {
    const { data, error } = await admin.storage.from(bucket).list(prefix, { limit: 1000, offset });
    if (error) throw error;
    out.push(...(data ?? []));
    if (!data || data.length < 1000) break;
  }
  return out;
}

interface DiagRow {
  id: string;
  object_path: string;
  status: string;
}

/** Rows that are due for removal, oldest first, bounded: `expired` = past expires_at; `pending` = reserved
 *  but never confirmed and older than the grace window. */
async function dueRows(admin: Admin, kind: "expired" | "pending", nowIso: string, pendingCutoffIso: string): Promise<DiagRow[]> {
  const out: DiagRow[] = [];
  for (let from = 0; out.length < DIAG_MAX_PER_RUN; from += 1000) {
    const base = admin.from("diagnostic_captures").select("id, object_path, status");
    const { data, error } = await (kind === "expired"
      ? base.lt("expires_at", nowIso).order("expires_at")
      : base.eq("status", "pending").lt("created_at", pendingCutoffIso).order("created_at")
    ).order("id").range(from, from + 999);
    if (error) throw error;
    out.push(...(data ?? []).map((r) => ({ id: r.id as string, object_path: r.object_path as string, status: r.status as string })));
    if (!data || data.length < 1000) break;
  }
  return out;
}

/** Retention for diagnostic captures. Never throws: a failure is reported in `error` so the (independent)
 *  preset-blob sweep still runs. */
async function sweepDiagnostics(admin: Admin, dry: boolean): Promise<DiagnosticsSweep> {
  const res: DiagnosticsSweep = {
    expiredRows: 0,
    stalePendingRows: 0,
    objectsRemoved: 0,
    rowsRemoved: 0,
    orphanObjects: 0,
    orphanObjectsRemoved: 0
  };
  try {
    // A. Rows due for removal.
    const nowIso = new Date().toISOString();
    const pendingCutoffIso = new Date(Date.now() - GRACE_MS).toISOString();
    const expired = await dueRows(admin, "expired", nowIso, pendingCutoffIso);
    const stale = await dueRows(admin, "pending", nowIso, pendingCutoffIso);
    res.expiredRows = expired.length;
    res.stalePendingRows = stale.length;

    if (!dry) {
      // Complete rows (expired): objects FIRST, then rows — if object removal fails the rows stay and the next
      // run retries (a missing object is not an error), so a row is never deleted while its object lives on.
      const complete = expired.filter((r) => r.status === "complete");
      for (let i = 0; i < complete.length; i += 100) {
        const batch = complete.slice(i, i + 100);
        const { data: gone, error: oerr } = await admin.storage.from(DIAG_BUCKET).remove(batch.map((r) => r.object_path));
        if (oerr) continue;
        res.objectsRemoved += gone?.length ?? 0;
        const { error: derr } = await admin
          .from("diagnostic_captures")
          .delete()
          .in("id", batch.map((r) => r.id))
          .eq("status", "complete");
        if (!derr) res.rowsRemoved += batch.length;
      }

      // Pending rows (stale reservations, or an expired one that never completed): ROWS first, and only rows
      // that are STILL pending — a client may have finalized one since it was selected, and then its object
      // must not be touched. The objects of the rows actually deleted are removed afterwards; if that fails
      // they become orphans, which step B (same grace) cleans up.
      const pendingRows = [...new Map([...stale, ...expired.filter((r) => r.status === "pending")].map((r) => [r.id, r])).values()];
      for (let i = 0; i < pendingRows.length; i += 100) {
        const batch = pendingRows.slice(i, i + 100);
        const { data: deleted, error: derr } = await admin
          .from("diagnostic_captures")
          .delete()
          .in("id", batch.map((r) => r.id))
          .eq("status", "pending")
          .lt("created_at", pendingCutoffIso)
          .select("id, object_path");
        if (derr) continue;
        res.rowsRemoved += deleted?.length ?? 0;
        const paths = (deleted ?? []).map((r) => r.object_path as string);
        if (!paths.length) continue;
        const { data: gone, error: oerr } = await admin.storage.from(DIAG_BUCKET).remove(paths);
        if (!oerr) res.objectsRemoved += gone?.length ?? 0;
      }
    }

    // B. Orphan objects: in the bucket but referenced by no row (of ANY status — a pending row's object is
    //    referenced). Loaded AFTER step A so objects it just removed are not listed; the grace window protects
    //    an upload between its reservation and its confirmation.
    const referenced = new Set<string>();
    for (let from = 0; ; from += 1000) {
      const { data, error } = await admin.from("diagnostic_captures").select("object_path").order("id").range(from, from + 999);
      if (error) throw error;
      for (const r of data ?? []) referenced.add(r.object_path as string);
      if (!data || data.length < 1000) break;
    }
    const cutoff = Date.now() - GRACE_MS;
    const orphans: string[] = [];
    for (const folder of (await listEntries(admin, DIAG_BUCKET, "")).filter((e) => !e.id)) {
      for (const f of (await listEntries(admin, DIAG_BUCKET, folder.name)).filter((e) => e.id)) {
        const path = `${folder.name}/${f.name}`;
        if (referenced.has(path)) continue;
        const created = f.created_at ? Date.parse(f.created_at) : 0;
        if (created > cutoff) continue; // grace window — may be an upload in flight
        orphans.push(path);
      }
    }
    res.orphanObjects = orphans.length;
    if (!dry) {
      for (let i = 0; i < orphans.length; i += 100) {
        const { data: gone, error } = await admin.storage.from(DIAG_BUCKET).remove(orphans.slice(i, i + 100));
        if (!error) res.orphanObjectsRemoved += gone?.length ?? 0;
      }
    }
  } catch (e) {
    res.error = e instanceof Error ? e.message : String((e as { message?: string })?.message ?? e);
  }
  return res;
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return new Response("method not allowed", { status: 405 });
  const secret = Deno.env.get("GC_SECRET");
  if (!secret || req.headers.get("x-gc-secret") !== secret) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "Content-Type": "application/json" } });
  }
  const dry = new URL(req.url).searchParams.get("dry") === "1";

  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false }
  });

  // Diagnostic-capture retention first and in isolation, so a problem in the preset-blob sweep below can
  // never starve it (and vice versa — it never throws).
  const diagnostics = await sweepDiagnostics(admin, dry);

  // Every referenced blob path, across all users (service role bypasses RLS).
  const referenced = new Set<string>();
  for (let from = 0; ; from += 1000) {
    const { data, error } = await admin.from("preset_versions").select("blob_path").range(from, from + 999);
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: { "Content-Type": "application/json" } });
    for (const r of data ?? []) referenced.add(r.blob_path as string);
    if (!data || data.length < 1000) break;
  }

  // Walk each user prefix in the bucket and diff.
  const cutoff = Date.now() - GRACE_MS;
  const orphans: string[] = [];
  const { data: users, error: lerr } = await admin.storage.from("preset-blobs").list("", { limit: 10000 });
  if (lerr) return new Response(JSON.stringify({ error: lerr.message }), { status: 500, headers: { "Content-Type": "application/json" } });
  for (const u of users ?? []) {
    if (!u.name) continue; // top level: one folder per user id
    const { data: files } = await admin.storage.from("preset-blobs").list(`${u.name}/blobs`, { limit: 10000 });
    for (const f of files ?? []) {
      const path = `${u.name}/blobs/${f.name}`;
      if (referenced.has(path)) continue;
      const created = f.created_at ? Date.parse(f.created_at) : 0;
      if (created > cutoff) continue; // grace window — may be a sync in flight
      orphans.push(path);
    }
  }

  let removed = 0;
  if (!dry && orphans.length) {
    for (let i = 0; i < orphans.length; i += 100) {
      const batch = orphans.slice(i, i + 100);
      const { error } = await admin.storage.from("preset-blobs").remove(batch);
      if (!error) removed += batch.length;
    }
  }
  return new Response(
    JSON.stringify({ ok: true, referenced: referenced.size, orphans: orphans.length, removed, dry, diagnostics }),
    { headers: { "Content-Type": "application/json" } }
  );
});
