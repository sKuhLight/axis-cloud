import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { BUCKET } from "./bundle.ts";
import { handleUpload, type UploadDeps } from "./handler.ts";

// Opt-in diagnostic capture upload (MT). A signed-in user uploads the redacted bundle their Axis/ForgeFX
// produced (gzip of JSON, `schema: 1`); this function validates it, stores the ORIGINAL gzip object in the
// private `diagnostic-captures` bucket at <user_id>/<capture_id>.json.gz and inserts a metadata row into
// `diagnostic_captures`. Request/response contract + limits: handler.ts. Behaviour is in handler.ts/
// bundle.ts (unit-testable); this file only wires the Supabase clients.
//
// verify_jwt is ON (config.toml): the platform rejects unauthenticated calls before this runs, and the user
// is ALSO resolved from the token here. Writes use the service role — neither the table nor the bucket has
// any client-facing policy, so the uploader can never read back (or list) captures; only the maintainer can,
// with the service role.

const url = Deno.env.get("SUPABASE_URL")!;
const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
// Token verification goes through the Auth server with the anon client (explicit jwt, no session state).
const verifier = createClient(url, anon, { auth: { persistSession: false, autoRefreshToken: false } });

const TABLE = "diagnostic_captures";

/** storage-js reports an existing object as HTTP 409 / "The resource already exists" (Duplicate). */
function isDuplicate(error: { message?: string; statusCode?: string | number; status?: number }): boolean {
  return String(error.statusCode ?? error.status) === "409" || /already exists|duplicate/i.test(error.message ?? "");
}

const deps: UploadDeps = {
  async authenticate(accessToken) {
    const { data, error } = await verifier.auth.getUser(accessToken);
    return error || !data.user ? null : { id: data.user.id };
  },

  async findCapture(userId, captureId) {
    const { data, error } = await admin
      .from(TABLE)
      .select("id")
      .eq("user_id", userId)
      .eq("capture_id", captureId)
      .maybeSingle();
    if (error) throw error;
    return data ? { id: data.id as string } : null;
  },

  async recentUploads(userId, sinceIso, limit) {
    const { data, error } = await admin
      .from(TABLE)
      .select("created_at")
      .eq("user_id", userId)
      .gte("created_at", sinceIso)
      .order("created_at", { ascending: false })
      .limit(limit);
    if (error) throw error;
    return (data ?? []).map((r) => r.created_at as string);
  },

  async putObject(path, body) {
    const { error } = await admin.storage.from(BUCKET).upload(path, body, {
      contentType: "application/gzip",
      upsert: false
    });
    if (!error) return "created";
    if (isDuplicate(error as { message?: string; statusCode?: string | number })) return "exists";
    throw error;
  },

  async removeObject(path) {
    const { error } = await admin.storage.from(BUCKET).remove([path]);
    if (error) throw error;
  },

  async insertCapture(row) {
    const { data, error } = await admin.from(TABLE).insert(row).select("id").single();
    if (error) {
      // 23505 = unique_violation on (user_id, capture_id): a concurrent identical upload got there first.
      if ((error as { code?: string }).code === "23505") return "conflict";
      throw error;
    }
    return { id: data.id as string };
  }
};

Deno.serve((req: Request) => handleUpload(req, deps));
