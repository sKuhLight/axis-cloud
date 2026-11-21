import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { type CaptureRecord, type Deps, handleRequest } from "./handler.ts";
import { BUCKET } from "./validate.ts";

// Opt-in diagnostic capture upload (MT) — signed-upload flow. The user's Axis/ForgeFX produced a redacted
// gzip bundle; it reaches the private `diagnostic-captures` bucket in three steps, none of which sends the
// bundle through this function:
//   reserve   POST /diagnostic-captures            validate + atomically reserve a row (rate limit, byte
//                                                  quota, dedup) + return a signed upload URL
//   upload    client -> storage                    the bucket enforces 25 MiB + application/gzip
//   finalize  POST /diagnostic-captures/finalize   check the object (exists, size, gzip magic) -> 'complete'
// Request/response contract and error codes: handler.ts. Behaviour lives in handler.ts / validate.ts
// (unit-testable); this file only wires the Supabase clients.
//
// verify_jwt is OFF (config.toml) on purpose: the handler authenticates the caller itself, before it reads
// anything, so every failure has the same `{ error: 'unauthorized' }` body (the platform check answers with
// its own differently-shaped body) and token verification does not depend on the project's JWT-signing mode.
// Writes use the service role — neither the table nor the bucket has any client-facing policy, so the
// uploader can never list or read captures back; only the maintainer can, with the service role.

const url = Deno.env.get("SUPABASE_URL")!;
const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
// Token verification goes through the Auth server with the anon client (explicit jwt, no session state).
const verifier = createClient(url, anon, { auth: { persistSession: false, autoRefreshToken: false } });

const TABLE = "diagnostic_captures";

type StorageErrorLike = { message?: string; statusCode?: string | number; status?: number };

/** storage-js reports an existing object as HTTP 409 / "The resource already exists" (Duplicate). */
function isDuplicate(error: StorageErrorLike): boolean {
  return String(error.statusCode ?? error.status) === "409" || /already exists|duplicate/i.test(error.message ?? "");
}

function isNotFound(error: StorageErrorLike): boolean {
  return String(error.statusCode ?? error.status) === "404" || /not.?found/i.test(error.message ?? "");
}

const deps: Deps = {
  async authenticate(accessToken) {
    const { data, error } = await verifier.auth.getUser(accessToken);
    return error || !data.user ? null : { id: data.user.id, isAnonymous: data.user.is_anonymous === true };
  },

  async reserve(a) {
    const { data, error } = await admin.rpc("reserve_diagnostic_capture", {
      p_user_id: a.userId,
      p_capture_id: a.captureId,
      p_model: a.model,
      p_firmware: a.firmware,
      p_app: a.app,
      p_state: a.state,
      p_bytes: a.bytes,
      p_max_per_window: a.maxPerWindow,
      p_window_seconds: a.windowSeconds,
      p_quota_bytes: a.quotaBytes,
      p_quota_window_seconds: a.quotaWindowSeconds,
      p_pending_charge_bytes: a.pendingChargeBytes,
      p_pending_max_age_seconds: a.pendingMaxAgeSeconds
    });
    if (error) {
      // Custom SQLSTATEs raised by the function: XQ001 = rate limit, XQ002 = byte quota; DETAIL = retry seconds.
      const e = error as { code?: string; details?: string };
      if (e.code === "XQ001" || e.code === "XQ002") {
        const retry = Number.parseInt(String(e.details ?? ""), 10);
        return {
          kind: "limited",
          reason: e.code === "XQ001" ? "rate" : "quota",
          retryAfterSeconds: Number.isFinite(retry) && retry > 0 ? retry : 60
        };
      }
      throw error;
    }
    const row = (Array.isArray(data) ? data[0] : data) as { row_id: string; row_status: string; deduped: boolean } | undefined;
    if (!row) throw new Error("reserve_diagnostic_capture returned no row");
    return {
      kind: "ok",
      id: row.row_id,
      status: row.row_status === "complete" ? "complete" : "pending",
      deduped: row.deduped === true
    };
  },

  async createUpload(path) {
    // No upsert: an existing object at the path is never overwritten.
    const { data, error } = await admin.storage.from(BUCKET).createSignedUploadUrl(path);
    if (error) {
      if (isDuplicate(error as StorageErrorLike)) return "exists";
      throw error;
    }
    return { uploadUrl: data.signedUrl, token: data.token };
  },

  async getCapture(userId, rowId) {
    const { data, error } = await admin
      .from(TABLE)
      .select("id, capture_id, status, bytes, object_path")
      .eq("id", rowId)
      .eq("user_id", userId)
      .maybeSingle();
    if (error) throw error;
    if (!data) return null;
    const rec: CaptureRecord = {
      id: data.id as string,
      captureId: data.capture_id as string,
      status: data.status === "complete" ? "complete" : "pending",
      bytes: data.bytes as number,
      objectPath: data.object_path as string
    };
    return rec;
  },

  async statObject(path) {
    const { data, error } = await admin.storage.from(BUCKET).info(path);
    if (error) {
      if (isNotFound(error as StorageErrorLike)) return null;
      throw error;
    }
    // A missing/garbled size must not be read as "0 bytes" or "no object": fail loudly (-> 500, logged).
    const size = Number(data.size);
    if (!Number.isFinite(size) || size < 0) throw new Error("storage returned no usable object size");
    return { size };
  },

  async readHead(path, n) {
    // A short-lived signed GET URL + a Range request; the stream is cancelled after n bytes, so even a
    // server that ignored Range would not make us buffer the object.
    const { data, error } = await admin.storage.from(BUCKET).createSignedUrl(path, 60);
    if (error) {
      if (isNotFound(error as StorageErrorLike)) return null;
      throw error;
    }
    const res = await fetch(data.signedUrl, { headers: { Range: `bytes=0-${n - 1}` } });
    if (res.status === 404) {
      await res.body?.cancel();
      return null;
    }
    if (!res.ok || !res.body) throw new Error(`storage range read failed: ${res.status}`);
    const reader = res.body.getReader();
    const head = new Uint8Array(n);
    let got = 0;
    while (got < n) {
      const { done, value } = await reader.read();
      if (done) break;
      const take = Math.min(value.byteLength, n - got);
      head.set(value.subarray(0, take), got);
      got += take;
    }
    await reader.cancel().catch(() => {});
    return head.subarray(0, got);
  },

  async removeObject(path) {
    const { error } = await admin.storage.from(BUCKET).remove([path]);
    if (error) throw error;
  },

  async completeCapture(userId, rowId, bytes) {
    const { data, error } = await admin
      .from(TABLE)
      .update({ status: "complete", bytes })
      .eq("id", rowId)
      .eq("user_id", userId)
      .eq("status", "pending")
      .select("id");
    if (error) throw error;
    return (data ?? []).length > 0;
  }
};

Deno.serve((req: Request) => handleRequest(req, deps));
