import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { type CoverageState, DEFAULT_CONFIG, type Deps, handleRequest, type HandlerConfig, type UploadRecord } from "./handler.ts";
import { BUCKET, DEFAULT_IP_HEADERS, MIN_IP_SALT_LENGTH } from "./validate.ts";

// Editor definitions-cache contributions (MP) — signed-upload flow. Request/response contract, error codes and
// the checks: handler.ts. Structure/redaction check, network key, limits: validate.ts. This file only wires the
// Supabase clients and reads the configuration.
//
// verify_jwt is OFF (config.toml): GET is public, and the handler authenticates every other request itself
// before it reads anything (so every auth failure has the same `{ error: 'unauthorized' }` body). Writes use the
// service role — neither the tables nor the bucket have any client-facing policy.
//
// Function secrets (`supabase secrets set …` on a hosted project; an env file for `functions serve` locally):
//   EDITOR_CACHE_IP_SALT      REQUIRED, ≥ 32 characters (e.g. 64 random hex). Secret for the keyed hash of the
//                             client network (per-network limits, one-network-counts-once coverage). Missing or
//                             shorter: wanted:false / 503 paused. Rotating it resets the per-network counters.
//   EDITOR_CACHE_UPLOADS      `off` = global kill switch (status wanted:false, reserve/finalize 503 paused;
//                             listing and deleting keep working).
//   EDITOR_CACHE_ALLOW_ANONYMOUS  `0`/`false` = refuse anonymous sessions (403 account-required). Default: allowed.
//   EDITOR_CACHE_IP_HEADERS   comma-separated request headers to read the client address from (default
//                             cf-connecting-ip,x-real-ip,x-forwarded-for — for x-forwarded-for the LAST entry).
//                             PIN it to the one header the platform's proxy sets once a staging run has shown
//                             which it is (the first reservation per isolate logs the header NAMES present).

const url = Deno.env.get("SUPABASE_URL")!;
const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
// Token verification goes through the Auth server with the anon client (explicit jwt, no session state).
const verifier = createClient(url, anon, { auth: { persistSession: false, autoRefreshToken: false } });

const TABLE = "editor_cache_uploads";

const ipSalt = Deno.env.get("EDITOR_CACHE_IP_SALT") ?? "";
if (ipSalt.length < MIN_IP_SALT_LENGTH) {
  console.error(`editor-caches: EDITOR_CACHE_IP_SALT is missing or shorter than ${MIN_IP_SALT_LENGTH} characters — uploads are paused until it is set`);
}
const ipHeaders = (Deno.env.get("EDITOR_CACHE_IP_HEADERS") ?? "")
  .split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
const allowAnonymousEnv = (Deno.env.get("EDITOR_CACHE_ALLOW_ANONYMOUS") ?? "").trim().toLowerCase();

const config: HandlerConfig = {
  ...DEFAULT_CONFIG,
  enabled: (Deno.env.get("EDITOR_CACHE_UPLOADS") ?? "").trim().toLowerCase() !== "off",
  allowAnonymous: !(allowAnonymousEnv === "0" || allowAnonymousEnv === "false" || allowAnonymousEnv === "off"),
  ipSalt: ipSalt || null,
  ipHeaders: ipHeaders.length ? ipHeaders : DEFAULT_IP_HEADERS
};

type StorageErrorLike = { message?: string; statusCode?: string | number; status?: number };

/** storage-js reports an existing object as HTTP 409 / "The resource already exists" (Duplicate). */
function isDuplicate(error: StorageErrorLike): boolean {
  return String(error.statusCode ?? error.status) === "409" || /already exists|duplicate/i.test(error.message ?? "");
}

function isNotFound(error: StorageErrorLike): boolean {
  return String(error.statusCode ?? error.status) === "404" || /not.?found/i.test(error.message ?? "");
}

const ROW_COLUMNS = "id, status, bytes, object_path, sha256, model, device_firmware, file_version, content_version";

function toRecord(d: Record<string, unknown>): UploadRecord {
  return {
    id: d.id as string,
    status: d.status === "complete" ? "complete" : "pending",
    bytes: d.bytes as number,
    objectPath: d.object_path as string,
    sha256: d.sha256 as string,
    model: d.model as number,
    deviceFirmware: d.device_firmware as string,
    fileVersion: (d.file_version as string | null) ?? null,
    contentVersion: (d.content_version as string | null) ?? null
  };
}

const deps: Deps = {
  async authenticate(accessToken) {
    const { data, error } = await verifier.auth.getUser(accessToken);
    return error || !data.user ? null : { id: data.user.id, isAnonymous: data.user.is_anonymous === true };
  },

  async coverageState(model, firmware) {
    const { data, error } = await admin
      .from("editor_cache_coverage")
      .select("state")
      .eq("model", model)
      .eq("device_firmware", firmware)
      .maybeSingle();
    if (error) throw error;
    if (!data) return null;
    const s = data.state as string;
    return (s === "covered" || s === "closed" ? s : "collecting") as CoverageState;
  },

  async reserve(a) {
    const { data, error } = await admin.rpc("reserve_editor_cache_upload", {
      p_user_id: a.userId,
      p_ip_key: a.ipKey,
      p_model: a.model,
      p_device_firmware: a.deviceFirmware,
      p_file_version: a.fileVersion,
      p_content_version: a.contentVersion,
      p_file_name: a.fileName,
      p_sha256: a.sha256,
      p_bytes: a.bytes,
      p_redaction: a.redaction,
      p_summary: a.summary,
      p_app: a.app,
      p_consent_at: a.consentAt,
      p_consent_version: a.consentVersion,
      p_max_per_window: a.maxPerWindow,
      p_window_seconds: a.windowSeconds,
      p_quota_bytes: a.quotaBytes,
      p_quota_window_seconds: a.quotaWindowSeconds,
      p_pending_charge_bytes: a.pendingChargeBytes,
      p_pending_max_age_seconds: a.pendingMaxAgeSeconds,
      p_per_firmware_max: a.perFirmwareMax,
      p_ip_max_per_window: a.ipMaxPerWindow,
      p_ip_quota_bytes: a.ipQuotaBytes
    });
    if (error) {
      // Custom SQLSTATEs (DETAIL = retry seconds for the limits): XQ001/XQ002 uploader rate/quota,
      // XQ005/XQ006 network rate/quota, XQ003 not wanted, XQ004 per-firmware limit.
      const e = error as { code?: string; details?: string };
      if (e.code === "XQ003") return { kind: "not-wanted" };
      if (e.code === "XQ004") return { kind: "firmware-limit" };
      if (e.code === "XQ001" || e.code === "XQ002" || e.code === "XQ005" || e.code === "XQ006") {
        const retry = Number.parseInt(String(e.details ?? ""), 10);
        return {
          kind: "limited",
          reason: e.code === "XQ001" || e.code === "XQ005" ? "rate" : "quota",
          scope: e.code === "XQ005" || e.code === "XQ006" ? "ip" : "uploader",
          retryAfterSeconds: Number.isFinite(retry) && retry > 0 ? retry : 60
        };
      }
      throw error;
    }
    const row = (Array.isArray(data) ? data[0] : data) as { row_id: string | null; row_status: string; deduped: boolean } | undefined;
    if (!row) throw new Error("reserve_editor_cache_upload returned no row");
    return {
      kind: "ok",
      id: row.row_id ?? null,
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

  async getUpload(userId, rowId) {
    const { data, error } = await admin
      .from(TABLE)
      .select(ROW_COLUMNS)
      .eq("id", rowId)
      .eq("user_id", userId)
      .maybeSingle();
    if (error) throw error;
    return data ? toRecord(data as Record<string, unknown>) : null;
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

  async readObject(path, maxBytes) {
    // A short-lived signed GET URL; the stream is cancelled once maxBytes have arrived, so the object is never
    // buffered beyond the cap (+1, which the handler uses to detect an over-size object).
    const { data, error } = await admin.storage.from(BUCKET).createSignedUrl(path, 60);
    if (error) {
      if (isNotFound(error as StorageErrorLike)) return null;
      throw error;
    }
    const res = await fetch(data.signedUrl);
    if (res.status === 404 || res.status === 400) {
      await res.body?.cancel();
      return null;
    }
    if (!res.ok || !res.body) throw new Error(`storage read failed: ${res.status}`);
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let got = 0;
    while (got < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      const take = Math.min(value.byteLength, maxBytes - got);
      chunks.push(take === value.byteLength ? value : value.subarray(0, take));
      got += take;
    }
    await reader.cancel().catch(() => {});
    const out = new Uint8Array(got);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.byteLength;
    }
    return out;
  },

  async complete(a) {
    const { data, error } = await admin.rpc("complete_editor_cache_upload", {
      p_user_id: a.userId,
      p_row_id: a.rowId,
      p_bytes: a.bytes,
      p_content_version: a.contentVersion,
      p_threshold: a.threshold
    });
    if (error) throw error;
    const row = (Array.isArray(data) ? data[0] : data) as { row_status: string; covered: boolean } | undefined;
    if (!row) return null;
    return { status: row.row_status === "complete" ? "complete" : "pending", covered: row.covered === true };
  },

  async removeObject(path) {
    const { error } = await admin.storage.from(BUCKET).remove([path]);
    if (error) throw error;
  },

  async deleteUpload(userId, rowId) {
    const { data, error } = await admin
      .from(TABLE)
      .delete()
      .eq("id", rowId)
      .eq("user_id", userId)
      .select("id");
    if (error) throw error;
    return (data ?? []).length > 0;
  },

  async listUploads(userId, limit) {
    const { data, error } = await admin
      .from(TABLE)
      .select("id, model, device_firmware, file_version, content_version, version_match, file_name, sha256, bytes, status, created_at, expires_at")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(limit);
    if (error) throw error;
    return (data ?? []).map((d) => ({
      uploadId: d.id as string,
      model: d.model as number,
      deviceFirmware: d.device_firmware as string,
      fileVersion: (d.file_version as string | null) ?? null,
      contentVersion: (d.content_version as string | null) ?? null,
      versionMatch: d.version_match === true,
      fileName: d.file_name as string,
      sha256: d.sha256 as string,
      bytes: d.bytes as number,
      status: d.status === "complete" ? "complete" : "pending",
      createdAt: d.created_at as string,
      expiresAt: d.expires_at as string
    }));
  }
};

Deno.serve((req: Request) => handleRequest(req, deps, config));
