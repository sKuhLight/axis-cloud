import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

// Orphan-blob sweep. Quota enforcement is metadata-gated (a preset_versions BEFORE INSERT trigger),
// so an interrupted or rejected sync can leave a blob in Storage with no metadata row referencing
// it. Such blobs are invisible to the app (everything resolves via preset_versions.blob_path) but
// cost storage — this function removes any blob not referenced by a blob_path, skipping objects
// younger than 24 h so it never races an in-flight sync that uploads blob-before-metadata.
//
// NOT user-facing: gated by a shared secret header (GC_SECRET env), meant for manual invocation or
// a schedule (pg_cron / dashboard scheduled trigger). Pass ?dry=1 to report without deleting.
const GRACE_MS = 24 * 60 * 60 * 1000;

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
    JSON.stringify({ ok: true, referenced: referenced.size, orphans: orphans.length, removed, dry }),
    { headers: { "Content-Type": "application/json" } }
  );
});
