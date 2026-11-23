import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient, type SupabaseClient } from "jsr:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";

// GDPR Art. 17 — erase the caller's account + all their data. JWT-gated (verify_jwt); the caller is
// identified from their own token, so a user can only ever delete themselves. Runs with the service role
// (server-side only) to remove the auth user + rows the anon key can't touch.

type Admin = SupabaseClient;

// Removes every object under `<prefix>/` in a bucket, paging until it is empty. Best-effort like the rest of
// this function: a failure is LOGGED and stops the loop (the account deletion still proceeds). For the
// diagnostic-captures and editor-caches buckets the gc-blobs sweep then removes the leftovers: once their rows are
// gone they are unreferenced, and it deletes unreferenced objects older than 24 h on its next scheduled run.
async function removeAllUnder(admin: Admin, bucket: string, prefix: string): Promise<void> {
  for (let round = 0; round < 100; round++) {
    const { data: files, error } = await admin.storage.from(bucket).list(prefix, { limit: 1000 });
    if (error) {
      console.error(`delete-account: listing ${bucket} objects failed:`, error.message);
      return;
    }
    // Entries without an id are "folders"; the bucket layout is flat under <uid>/.
    const paths = (files ?? []).filter((f) => f.id).map((f) => `${prefix}/${f.name}`);
    if (!paths.length) return;
    const { error: rerr } = await admin.storage.from(bucket).remove(paths);
    if (rerr) {
      console.error(`delete-account: removing ${bucket} objects failed:`, rerr.message);
      return;
    }
  }
  console.error(`delete-account: ${bucket} still had objects after 100 rounds; leaving the rest to gc-blobs`);
}

Deno.serve(async (req: Request) => {
  const cors = corsHeaders("POST, OPTIONS");
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return new Response("method not allowed", { status: 405, headers: cors });

  const url = Deno.env.get("SUPABASE_URL")!;
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const authHeader = req.headers.get("Authorization") ?? "";

  // Identify the caller from their JWT — they can only delete themselves.
  const userClient = createClient(url, anon, { global: { headers: { Authorization: authHeader } } });
  const { data: { user }, error: uerr } = await userClient.auth.getUser();
  if (uerr || !user) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { ...cors, "Content-Type": "application/json" } });
  const uid = user.id;

  const admin = createClient(url, service, { auth: { persistSession: false } });

  // 1. Remove the user's preset blobs from storage (<uid>/blobs/*).
  try {
    const { data: files } = await admin.storage.from("preset-blobs").list(`${uid}/blobs`, { limit: 10000 });
    if (files && files.length) {
      await admin.storage.from("preset-blobs").remove(files.map((f) => `${uid}/blobs/${f.name}`));
    }
  } catch (_) { /* best-effort — continue */ }

  // 1b. Remove the user's diagnostic captures from the private bucket (<uid>/<capture_id>.json.gz). The rows
  //     below go with them; both together are the user's whole diagnostic footprint.
  try {
    await removeAllUnder(admin, "diagnostic-captures", uid);
  } catch (e) {
    console.error("delete-account: removing diagnostic captures failed:", e instanceof Error ? e.message : e);
  }

  // 1c. Remove the user's editor-cache uploads (<uid>/<sha256>.cache). Works the same for an anonymous session —
  //     that is how an anonymous uploader erases everything at once. Leftovers are swept by gc-blobs as above.
  try {
    await removeAllUnder(admin, "editor-caches", uid);
  } catch (e) {
    console.error("delete-account: removing editor-cache uploads failed:", e instanceof Error ? e.message : e);
  }

  // 1d. Shared device definitions: withdraw the user's contributions FIRST, through the SQL function — it takes the
  //     per-source locks in a fixed order and deletes the sources this leaves without contributions (unless the
  //     maintainer pinned them) in the same transaction. Deleting the auth user would cascade the rows too, but in
  //     delete order (deadlock-prone against a concurrent share) and leaving orphans for the cleanup. Then the
  //     user's spot-check reports. Best-effort and logged: the auth-user cascade below still removes both.
  try {
    const { error } = await admin.rpc("withdraw_definition_contributions", { p_user_id: uid });
    if (error) console.error("delete-account: withdrawing shared definitions failed:", error.message);
  } catch (e) {
    console.error("delete-account: withdrawing shared definitions failed:", e instanceof Error ? e.message : e);
  }

  // 2. Delete the user's rows (explicit; safe regardless of FK cascade). Deleting editor_cache_uploads clears the
  //    link of its per-network rate-limit counters (they carry no user id and age out after 30 days); the
  //    definition-source network counters carry no user id either and age out the same way.
  for (const table of ["documents", "preset_versions", "backups", "subscriptions", "diagnostic_captures", "editor_cache_uploads", "definition_source_reports"]) {
    const { error } = await admin.from(table).delete().eq("user_id", uid);
    if (error) console.error(`delete-account: deleting ${table} rows failed:`, error.message);
  }

  // 3. Delete the auth user itself (erases the email; cascades whatever a failed step above left behind).
  const { error: derr } = await admin.auth.admin.deleteUser(uid);
  if (derr) return new Response(JSON.stringify({ error: derr.message }), { status: 500, headers: { ...cors, "Content-Type": "application/json" } });

  // 4. Shared sources left without contributions (only when step 1d failed and the cascade removed the votes):
  //    the public policy hides them at once; delete them now rather than at the next gc-blobs run. Best-effort.
  try {
    const { error } = await admin.rpc("cleanup_orphan_definition_sources");
    if (error) console.error("delete-account: orphan cleanup of shared definitions failed:", error.message);
  } catch (e) {
    console.error("delete-account: orphan cleanup of shared definitions failed:", e instanceof Error ? e.message : e);
  }

  return new Response(JSON.stringify({ ok: true, deleted: uid }), { headers: { ...cors, "Content-Type": "application/json" } });
});
