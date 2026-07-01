import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

// GDPR Art. 17 — erase the caller's account + all their data. JWT-gated (verify_jwt); the caller is
// identified from their own token, so a user can only ever delete themselves. Runs with the service role
// (server-side only) to remove the auth user + rows the anon key can't touch.
Deno.serve(async (req: Request) => {
  const cors: Record<string, string> = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "authorization, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS"
  };
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

  // 2. Delete the user's rows (explicit; safe regardless of FK cascade).
  for (const table of ["documents", "preset_versions", "backups", "subscriptions"]) {
    await admin.from(table).delete().eq("user_id", uid);
  }

  // 3. Delete the auth user itself (erases the email).
  const { error: derr } = await admin.auth.admin.deleteUser(uid);
  if (derr) return new Response(JSON.stringify({ error: derr.message }), { status: 500, headers: { ...cors, "Content-Type": "application/json" } });

  return new Response(JSON.stringify({ ok: true, deleted: uid }), { headers: { ...cors, "Content-Type": "application/json" } });
});
