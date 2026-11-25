import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient, type SupabaseClient } from "jsr:@supabase/supabase-js@2";
import { ownersAmong } from "./owners.ts";

// Orphan-blob sweep. Quota enforcement is metadata-gated (a preset_versions BEFORE INSERT trigger),
// so an interrupted or rejected sync can leave a blob in Storage with no metadata row referencing
// it. Such blobs are invisible to the app (everything resolves via preset_versions.blob_path) but
// cost storage — this function removes any blob not referenced by a blob_path, skipping objects
// younger than 24 h so it never races an in-flight sync that uploads blob-before-metadata.
//
// It also enforces the retention of the two private upload stores — diagnostic captures (MT, table
// `diagnostic_captures`, bucket `diagnostic-captures`) and editor-cache uploads (MP, table `editor_cache_uploads`,
// bucket `editor-caches`) — with one routine, sweepPrivateUploads(): rows past `expires_at` are deleted together
// with their object; reservations whose upload was never confirmed (`status = 'pending'`) are removed after the
// same 24 h grace; and objects no row references any more (a crashed upload, or leftovers after account deletion
// cascaded the rows away) are removed after that grace too. Results are reported under `diagnostics` and
// `editorCaches`. Finally the per-network rate-limit counters of editor-cache uploads (`editor_cache_ip_usage`:
// keyed hashes, no user id) are deleted once unlinked from an upload and older than the longest limit window
// (30 days), reported under `editorCacheNetworkCounters`.
//
// Shared device definitions (cloud v2, `definition_sources` + private contributions/reports/network counters):
// `unlink_expired_definition_contributions()` unlinks contributions older than their 180-day link (user id and
// network key nulled; the public content and its counts stay), deletes spot-check reports older than 180 days and
// network counters older than 30 days; `cleanup_orphan_definition_sources()` deletes sources left without any
// contribution (unless the maintainer pinned them). Reported under `definitionSources`.
//
// And it deletes Supabase ANONYMOUS auth users (editor-cache uploaders and definition sharers without an account)
// that own nothing in the upload stores — no upload, no LINKED definition contribution — and have not signed in for
// ANONYMOUS_USER_IDLE_DAYS (default 30; `off` disables), via the Auth admin API, reported under `anonymousUsers`. Supabase Auth keeps the client IP of every session it issues
// (sessions are deleted with the user); this bounds how long such records linger for a contribution that is
// already gone. Auth's own audit log is NOT removed by this (see README "Anonymous sessions").
//
// NOT user-facing: gated by a shared secret header (GC_SECRET env), meant for manual invocation or
// a schedule (pg_cron / dashboard scheduled trigger; recommended: once a day). Pass ?dry=1 to report
// without deleting.
const GRACE_MS = 24 * 60 * 60 * 1000;

// Bounds one run per category and store (rows are removed oldest-first; the remainder is picked up by the next run).
const MAX_PER_RUN = 5000;
/** Editor-cache network counters are only needed for the longest limit window (the 30-day byte quota) once
 *  their upload is gone; while it exists they are kept (coverage counts each network once). */
const NETWORK_COUNTER_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
/** Retention of definition-source spot-check reports and network counters (= the SQL function's defaults). */
const DEFINITION_REPORT_MAX_AGE_MS = 180 * 24 * 60 * 60 * 1000;
const DEFINITION_USAGE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
/** Anonymous auth users idle this many days with no remaining uploads are deleted (env ANONYMOUS_USER_IDLE_DAYS). */
const DEFAULT_ANONYMOUS_USER_IDLE_DAYS = 30;
/** Auth admin listUsers pages per run (1000 users each); the rest is handled by the next run. */
const ANONYMOUS_USER_MAX_PAGES = 50;

/** A private upload store: a table of rows with `object_path`, `status`, `created_at`, `expires_at`, and its bucket. */
interface UploadStore {
  table: string;
  bucket: string;
}
const DIAGNOSTICS: UploadStore = { table: "diagnostic_captures", bucket: "diagnostic-captures" };
const EDITOR_CACHES: UploadStore = { table: "editor_cache_uploads", bucket: "editor-caches" };

type Admin = SupabaseClient;

interface UploadSweep {
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

interface UploadRow {
  id: string;
  object_path: string;
  status: string;
}

/** Rows that are due for removal, oldest first, bounded: `expired` = past expires_at; `pending` = reserved
 *  but never confirmed and older than the grace window. */
async function dueRows(
  admin: Admin,
  store: UploadStore,
  kind: "expired" | "pending",
  nowIso: string,
  pendingCutoffIso: string
): Promise<UploadRow[]> {
  const out: UploadRow[] = [];
  for (let from = 0; out.length < MAX_PER_RUN; from += 1000) {
    const base = admin.from(store.table).select("id, object_path, status");
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

/** Retention for one private upload store. Never throws: a failure is reported in `error` so the (independent)
 *  other sweeps still run. */
async function sweepPrivateUploads(admin: Admin, dry: boolean, store: UploadStore): Promise<UploadSweep> {
  const res: UploadSweep = {
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
    const expired = await dueRows(admin, store, "expired", nowIso, pendingCutoffIso);
    const stale = await dueRows(admin, store, "pending", nowIso, pendingCutoffIso);
    res.expiredRows = expired.length;
    res.stalePendingRows = stale.length;

    if (!dry) {
      // Complete rows (expired): objects FIRST, then rows — if object removal fails the rows stay and the next
      // run retries (a missing object is not an error), so a row is never deleted while its object lives on.
      const complete = expired.filter((r) => r.status === "complete");
      for (let i = 0; i < complete.length; i += 100) {
        const batch = complete.slice(i, i + 100);
        const { data: gone, error: oerr } = await admin.storage.from(store.bucket).remove(batch.map((r) => r.object_path));
        if (oerr) continue;
        res.objectsRemoved += gone?.length ?? 0;
        const { data: deleted, error: derr } = await admin
          .from(store.table)
          .delete()
          .in("id", batch.map((r) => r.id))
          .eq("status", "complete")
          .select("id");
        if (!derr) res.rowsRemoved += deleted?.length ?? 0;
      }

      // Pending rows (stale reservations, or an expired one that never completed): ROWS first, and only rows
      // that are STILL pending — a client may have finalized one since it was selected, and then its object
      // must not be touched. The objects of the rows actually deleted are removed afterwards; if that fails
      // they become orphans, which step B (same grace) cleans up.
      const pendingRows = [...new Map([...stale, ...expired.filter((r) => r.status === "pending")].map((r) => [r.id, r])).values()];
      for (let i = 0; i < pendingRows.length; i += 100) {
        const batch = pendingRows.slice(i, i + 100);
        const { data: deleted, error: derr } = await admin
          .from(store.table)
          .delete()
          .in("id", batch.map((r) => r.id))
          .eq("status", "pending")
          .lt("created_at", pendingCutoffIso)
          .select("id, object_path");
        if (derr) continue;
        res.rowsRemoved += deleted?.length ?? 0;
        const paths = (deleted ?? []).map((r) => r.object_path as string);
        if (!paths.length) continue;
        const { data: gone, error: oerr } = await admin.storage.from(store.bucket).remove(paths);
        if (!oerr) res.objectsRemoved += gone?.length ?? 0;
      }
    }

    // B. Orphan objects: in the bucket but referenced by no row (of ANY status — a pending row's object is
    //    referenced). Loaded AFTER step A so objects it just removed are not listed; the grace window protects
    //    an upload between its reservation and its confirmation.
    const referenced = new Set<string>();
    for (let from = 0; ; from += 1000) {
      const { data, error } = await admin.from(store.table).select("object_path").order("id").range(from, from + 999);
      if (error) throw error;
      for (const r of data ?? []) referenced.add(r.object_path as string);
      if (!data || data.length < 1000) break;
    }
    const cutoff = Date.now() - GRACE_MS;
    const orphans: string[] = [];
    for (const folder of (await listEntries(admin, store.bucket, "")).filter((e) => !e.id)) {
      for (const f of (await listEntries(admin, store.bucket, folder.name)).filter((e) => e.id)) {
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
        const { data: gone, error } = await admin.storage.from(store.bucket).remove(orphans.slice(i, i + 100));
        if (!error) res.orphanObjectsRemoved += gone?.length ?? 0;
      }
    }
  } catch (e) {
    res.error = e instanceof Error ? e.message : String((e as { message?: string })?.message ?? e);
  }
  return res;
}

interface CounterPrune {
  expiredRows: number;
  rowsRemoved: number;
  error?: string;
}

/** Deletes editor-cache network counters that no upload references any more and that are older than the longest
 *  limit window. (Counters of existing uploads stay: coverage counts uploaders once per network.) Never throws. */
async function pruneNetworkCounters(admin: Admin, dry: boolean): Promise<CounterPrune> {
  const res: CounterPrune = { expiredRows: 0, rowsRemoved: 0 };
  try {
    const cutoffIso = new Date(Date.now() - NETWORK_COUNTER_MAX_AGE_MS).toISOString();
    const { count, error } = await admin
      .from("editor_cache_ip_usage")
      .select("id", { count: "exact", head: true })
      .is("upload_id", null)
      .lt("created_at", cutoffIso);
    if (error) throw error;
    res.expiredRows = count ?? 0;
    if (!dry && res.expiredRows > 0) {
      const { data, error: derr } = await admin
        .from("editor_cache_ip_usage")
        .delete()
        .is("upload_id", null)
        .lt("created_at", cutoffIso)
        .select("id");
      if (derr) throw derr;
      res.rowsRemoved = data?.length ?? 0;
    }
  } catch (e) {
    res.error = e instanceof Error ? e.message : String((e as { message?: string })?.message ?? e);
  }
  return res;
}

interface DefinitionSourcesSweep {
  /** Linked contributions past their 180-day link (dry run: would be unlinked). */
  expiredLinks: number;
  unlinked: number;
  /** Spot-check reports older than 180 days. */
  expiredReports: number;
  reportsDeleted: number;
  /** Per-network counters older than 30 days. */
  expiredUsage: number;
  usageDeleted: number;
  /** Sources without any contribution and not pinned. */
  orphans: number;
  orphansDeleted: number;
  error?: string;
}

/**
 * Retention of the shared definitions store: counts what is due, then (unless dry) runs the two SQL functions —
 * unlink first (it never creates orphans: an unlinked contribution still counts), then the orphan cleanup (sources
 * whose last contribution went with an account deletion the withdraw call did not cover). Runs BEFORE the
 * anonymous-user cleanup, so an anonymous sharer whose links just expired owns nothing any more and is deleted in
 * the same run. Never throws.
 */
async function sweepDefinitionSources(admin: Admin, dry: boolean): Promise<DefinitionSourcesSweep> {
  const res: DefinitionSourcesSweep = {
    expiredLinks: 0,
    unlinked: 0,
    expiredReports: 0,
    reportsDeleted: 0,
    expiredUsage: 0,
    usageDeleted: 0,
    orphans: 0,
    orphansDeleted: 0
  };
  try {
    const now = Date.now();
    const count = async (q: PromiseLike<{ count: number | null; error: unknown }>): Promise<number> => {
      const { count: n, error } = await q;
      if (error) throw error;
      return n ?? 0;
    };
    res.expiredLinks = await count(
      admin.from("definition_source_contributions").select("id", { count: "exact", head: true })
        .not("user_id", "is", null).lt("linked_until", new Date(now).toISOString())
    );
    res.expiredReports = await count(
      admin.from("definition_source_reports").select("id", { count: "exact", head: true })
        .lt("created_at", new Date(now - DEFINITION_REPORT_MAX_AGE_MS).toISOString())
    );
    res.expiredUsage = await count(
      admin.from("definition_source_network_usage").select("id", { count: "exact", head: true })
        .lt("created_at", new Date(now - DEFINITION_USAGE_MAX_AGE_MS).toISOString())
    );
    // contributors is recomputed on every removal of a contribution, so 0 = no contribution left.
    res.orphans = await count(
      admin.from("definition_sources").select("id", { count: "exact", head: true }).eq("contributors", 0).eq("pinned", false)
    );
    if (!dry) {
      const { data, error } = await admin.rpc("unlink_expired_definition_contributions");
      if (error) throw error;
      const row = (Array.isArray(data) ? data[0] : data) as { unlinked?: number; reports_deleted?: number; usage_deleted?: number } | undefined;
      res.unlinked = row?.unlinked ?? 0;
      res.reportsDeleted = row?.reports_deleted ?? 0;
      res.usageDeleted = row?.usage_deleted ?? 0;
      const { data: n, error: cerr } = await admin.rpc("cleanup_orphan_definition_sources");
      if (cerr) throw cerr;
      res.orphansDeleted = typeof n === "number" ? n : Number(n ?? 0);
    }
  } catch (e) {
    res.error = e instanceof Error ? e.message : String((e as { message?: string })?.message ?? e);
  }
  return res;
}

interface AnonymousUserCleanup {
  /** The idle threshold in days; null = disabled (ANONYMOUS_USER_IDLE_DAYS=off). */
  idleDays: number | null;
  scanned: number;
  candidates: number;
  deleted: number;
  error?: string;
}

/** Most recent activity Auth records for a user (last sign-in, else creation/update). */
function lastActivityMs(u: { last_sign_in_at?: string | null; created_at?: string; updated_at?: string | null }): number {
  const t = [u.last_sign_in_at, u.created_at, u.updated_at].map((s) => (s ? Date.parse(s) : NaN)).filter((n) => Number.isFinite(n));
  return t.length ? Math.max(...t) : Date.now(); // unknown activity: treat as active (never delete blindly)
}

/** Ids among `ids` that still own something: a row in one of the upload stores, or a LINKED definition
 *  contribution (an unlinked one has no user id). A linked one must survive: deleting the auth user would cascade
 *  it away, and with it the uploader's vote and possibly the public row. */
async function idsWithUploads(admin: Admin, ids: string[]): Promise<Set<string>> {
  // Answers are capped at the Data API's max-rows without an error: ownersAmong() asks for the exact count too and
  // re-asks for the users a truncated answer did not settle (owners.ts), failing closed when it cannot tell.
  return await ownersAmong(ids, [EDITOR_CACHES.table, DIAGNOSTICS.table, "definition_source_contributions"], async (table, chunk) => {
    const { data, error, count } = await admin.from(table).select("user_id", { count: "exact" }).in("user_id", [...chunk]);
    if (error) throw error;
    return { userIds: (data ?? []).map((r) => r.user_id as string), count: count ?? null };
  });
}

/**
 * Deletes anonymous auth users that are idle for ANONYMOUS_USER_IDLE_DAYS and own nothing in the upload stores and
 * no linked definition contribution. Accounts (is_anonymous false — including former anonymous users who linked an
 * e-mail) are never touched. Runs AFTER the upload sweeps and the definition unlink, so users whose uploads just
 * expired or whose links just ended qualify in the same run. Never throws.
 */
async function cleanupAnonymousUsers(admin: Admin, dry: boolean): Promise<AnonymousUserCleanup> {
  const raw = (Deno.env.get("ANONYMOUS_USER_IDLE_DAYS") ?? "").trim().toLowerCase();
  const disabled = raw === "off" || raw === "0";
  const days = /^\d{1,4}$/.test(raw) && Number(raw) > 0 ? Number(raw) : DEFAULT_ANONYMOUS_USER_IDLE_DAYS;
  const res: AnonymousUserCleanup = { idleDays: disabled ? null : days, scanned: 0, candidates: 0, deleted: 0 };
  if (disabled) return res;
  try {
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const idle: string[] = [];
    // Collect first, delete afterwards: deleting while paging would shift the pages.
    for (let page = 1; page <= ANONYMOUS_USER_MAX_PAGES; page++) {
      const { data, error } = await admin.auth.admin.listUsers({ page, perPage: 1000 });
      if (error) throw error;
      const users = data.users ?? [];
      res.scanned += users.length;
      for (const u of users) {
        if (u.is_anonymous === true && lastActivityMs(u) < cutoff) idle.push(u.id);
      }
      if (users.length < 1000) break;
    }
    const owning = await idsWithUploads(admin, idle);
    const candidates = idle.filter((id) => !owning.has(id));
    res.candidates = candidates.length;
    if (!dry) {
      for (const id of candidates) {
        const { error } = await admin.auth.admin.deleteUser(id);
        if (!error) res.deleted++;
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

  // Retention of the private upload stores first and in isolation, so a problem in the preset-blob sweep below
  // can never starve them (and vice versa — they never throw).
  const diagnostics = await sweepPrivateUploads(admin, dry, DIAGNOSTICS);
  const editorCaches = await sweepPrivateUploads(admin, dry, EDITOR_CACHES);
  const editorCacheNetworkCounters = await pruneNetworkCounters(admin, dry);
  const definitionSources = await sweepDefinitionSources(admin, dry);
  const anonymousUsers = await cleanupAnonymousUsers(admin, dry);

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
    JSON.stringify({
      ok: true,
      referenced: referenced.size,
      orphans: orphans.length,
      removed,
      dry,
      diagnostics,
      editorCaches,
      editorCacheNetworkCounters,
      definitionSources,
      anonymousUsers
    }),
    { headers: { "Content-Type": "application/json" } }
  );
});
