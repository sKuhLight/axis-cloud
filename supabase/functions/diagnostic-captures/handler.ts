// Request handling for `diagnostic-captures` (signed-upload flow), with every side effect behind `Deps` so
// the whole flow is testable with in-memory fakes (handler.test.ts). index.ts wires the Supabase adapter.
//
// The function never receives, decompresses or parses the gzip bundle (it can be up to 25 MiB; reading and
// parsing client-supplied compressed data in an edge worker is a memory-exhaustion risk, and this design
// does not rely on a hosted function accepting a body that large). It only handles small JSON requests:
//
//  1. POST  /diagnostic-captures            reserve
//       { captureId, model, firmware, app?, state?, bytes }   captureId = the bundle's own id (path-safe),
//                                                             bytes = exact size of the gzip to upload
//     200 { captureId, status: 'pending', uploadUrl, token, path, bucket, expiresIn }
//           captureId is the diagnostic_captures ROW id (use it for finalize). Add `deduped: true` when the
//           bundle id was reserved before (the client retries safely). The client then uploads the gzip to
//           storage: `PUT uploadUrl` (Content-Type: application/gzip) or storage-js
//           uploadToSignedUrl(path, token, body, { contentType: 'application/gzip' }).
//     200 { captureId, deduped: true, status: 'complete' }  already uploaded and confirmed: nothing to do
//     200 { captureId, deduped: true, status: 'pending' }   reserved and the object is already there (an
//           earlier attempt uploaded but did not finalize): skip the upload, call finalize
//     A repeat of a pending bundle id whose object is NOT there refreshes the announced `bytes` (so a
//     re-gzipped retry can finalize); a pending row older than ~20 h is recreated instead (new row id).
//  2. POST  /diagnostic-captures/finalize   (or ?action=finalize)
//       { captureId }   the row id from step 1
//     200 { captureId, status: 'complete' }  (idempotent)
//
//  Errors (JSON { error, message?, ... }):
//   400 invalid-request | invalid-json | empty-body | invalid-gzip   401 unauthorized
//   403 account-required (anonymous session)   404 not-found
//   409 not-uploaded | size-mismatch           413 too-large
//   429 rate-limited | quota-exceeded  (retryAfterSeconds + Retry-After header)
//   405 method-not-allowed                     500 internal
import {
  BUCKET,
  isGzip,
  MAX_JSON_BODY_BYTES,
  MAX_UPLOAD_BYTES,
  looksLikeJwt,
  objectPath,
  parseFinalizeRequest,
  parseReserveRequest,
  PENDING_REFRESH_MAX_AGE_SECONDS,
  QUOTA_BYTES,
  QUOTA_WINDOW_SECONDS,
  RATE_LIMIT_PER_WINDOW,
  RATE_WINDOW_SECONDS,
  readBodyCapped,
  SIGNED_UPLOAD_TTL_SECONDS
} from "./validate.ts";

export interface ReserveArgs {
  userId: string;
  captureId: string;
  model: number;
  firmware: string | null;
  app: Record<string, string>;
  state: string;
  bytes: number;
  maxPerWindow: number;
  windowSeconds: number;
  quotaBytes: number;
  quotaWindowSeconds: number;
  /** What an unconfirmed (pending) reservation counts against the quota: the full upload cap. */
  pendingChargeBytes: number;
  /** Pending rows older than this are recreated rather than reused (avoids racing gc-blobs' 24 h sweep). */
  pendingMaxAgeSeconds: number;
}

export type ReserveResult =
  | { kind: "ok"; id: string; status: "pending" | "complete"; deduped: boolean }
  | { kind: "limited"; reason: "rate" | "quota"; retryAfterSeconds: number };

/** The slice of a diagnostic_captures row the handler needs. */
export interface CaptureRecord {
  id: string;
  captureId: string;
  status: "pending" | "complete";
  /** Announced size while pending, actual size once complete. */
  bytes: number;
  objectPath: string;
}

export interface Deps {
  /** Resolve the user from the bearer token (Auth server round trip); null = invalid/expired. */
  authenticate(accessToken: string): Promise<{ id: string; isAnonymous: boolean } | null>;
  /** Atomic dedup + rate limit + quota + insert (the SQL function reserve_diagnostic_capture). */
  reserve(args: ReserveArgs): Promise<ReserveResult>;
  /** Signed upload URL for `path` (no overwrite). 'exists' = an object is already at that path. */
  createUpload(path: string): Promise<{ uploadUrl: string; token: string } | "exists">;
  /** The caller's own row by row id; null if absent or not theirs. */
  getCapture(userId: string, rowId: string): Promise<CaptureRecord | null>;
  /** Metadata of the stored object without downloading it; null if there is no such object. */
  statObject(path: string): Promise<{ size: number } | null>;
  /** The first `n` bytes of the object (a range read); null if there is no such object. */
  readHead(path: string, n: number): Promise<Uint8Array | null>;
  /** pending -> complete with the actual size; false if the row was not pending any more. */
  completeCapture(userId: string, rowId: string, bytes: number): Promise<boolean>;
  /** Delete the stored object (no error if it is already gone). */
  removeObject(path: string): Promise<void>;
}

export interface HandlerConfig {
  maxUploadBytes: number;
  maxJsonBodyBytes: number;
  rateLimitPerWindow: number;
  rateWindowSeconds: number;
  quotaBytes: number;
  quotaWindowSeconds: number;
  pendingMaxAgeSeconds: number;
}

export const DEFAULT_CONFIG: HandlerConfig = {
  maxUploadBytes: MAX_UPLOAD_BYTES,
  maxJsonBodyBytes: MAX_JSON_BODY_BYTES,
  rateLimitPerWindow: RATE_LIMIT_PER_WINDOW,
  rateWindowSeconds: RATE_WINDOW_SECONDS,
  quotaBytes: QUOTA_BYTES,
  quotaWindowSeconds: QUOTA_WINDOW_SECONDS,
  pendingMaxAgeSeconds: PENDING_REFRESH_MAX_AGE_SECONDS
};

const cors: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  // Retry-After is not CORS-safelisted: without this a browser client cannot read it on a 429.
  "Access-Control-Expose-Headers": "Retry-After"
};

function reply(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json", ...extra }
  });
}

function fail(status: number, error: string, extra: Record<string, unknown> = {}): Response {
  return reply(status, { error, ...extra });
}

type User = { id: string };

/** Authenticates BEFORE any body is read. Anonymous sessions are real JWTs but not accounts. */
async function authorize(req: Request, deps: Deps): Promise<{ user: User } | { res: Response }> {
  const token = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "")?.[1];
  // A malformed token cannot be valid: refuse it without an Auth-server round trip.
  if (!token || !looksLikeJwt(token)) return { res: fail(401, "unauthorized") };
  const user = await deps.authenticate(token);
  if (!user) return { res: fail(401, "unauthorized") };
  if (user.isAnonymous) {
    return { res: fail(403, "account-required", { message: "diagnostic uploads need a signed-in account, not an anonymous session" }) };
  }
  return { user };
}

/** Reads the (tiny) JSON request body with a hard cap. */
async function readJson(req: Request, cfg: HandlerConfig): Promise<{ body: unknown } | { res: Response }> {
  const tooLarge = () => ({ res: fail(413, "too-large", { stage: "request", limit: cfg.maxJsonBodyBytes }) });
  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > cfg.maxJsonBodyBytes) return tooLarge();
  const raw = await readBodyCapped(req.body, cfg.maxJsonBodyBytes);
  if (raw === null) return tooLarge();
  if (raw.length === 0) return { res: fail(400, "empty-body", { message: "request body is empty" }) };
  try {
    return { body: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)) };
  } catch {
    return { res: fail(400, "invalid-json", { message: "request body is not valid UTF-8 JSON" }) };
  }
}

export async function handleRequest(req: Request, deps: Deps, cfg: HandlerConfig = DEFAULT_CONFIG): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return reply(405, { error: "method-not-allowed" }, { Allow: "POST, OPTIONS" });

  try {
    const url = new URL(req.url);
    const finalize = url.pathname.replace(/\/+$/, "").endsWith("/finalize") || url.searchParams.get("action") === "finalize";

    const auth = await authorize(req, deps);
    if ("res" in auth) return auth.res;
    const body = await readJson(req, cfg);
    if ("res" in body) return body.res;

    return finalize
      ? await finalizeCapture(auth.user, body.body, deps, cfg)
      : await reserveCapture(auth.user, body.body, deps, cfg);
  } catch (e) {
    // Details go to the function log (maintainer-only), never to the client.
    console.error("diagnostic-captures:", e instanceof Error ? e.message : e);
    return fail(500, "internal", { message: "request failed; please try again later" });
  }
}

async function reserveCapture(user: User, rawBody: unknown, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const parsed = parseReserveRequest(rawBody, cfg.maxUploadBytes);
  if (!parsed.ok) {
    return fail(parsed.status, parsed.error, { message: parsed.message, ...(parsed.limit !== undefined ? { limit: parsed.limit } : {}) });
  }
  const r = parsed.value;

  // Atomic in the database: dedup, rate limit, byte quota, insert (per-user lock — parallel requests
  // cannot race past the limits).
  const reserved = await deps.reserve({
    userId: user.id,
    captureId: r.captureId,
    model: r.model,
    firmware: r.firmware,
    app: r.app,
    state: r.state,
    bytes: r.bytes,
    maxPerWindow: cfg.rateLimitPerWindow,
    windowSeconds: cfg.rateWindowSeconds,
    quotaBytes: cfg.quotaBytes,
    quotaWindowSeconds: cfg.quotaWindowSeconds,
    // The announced size is unverified until finalize, so an unconfirmed reservation is charged at the cap.
    pendingChargeBytes: cfg.maxUploadBytes,
    pendingMaxAgeSeconds: cfg.pendingMaxAgeSeconds
  });
  if (reserved.kind === "limited") {
    const retryAfterSeconds = Math.max(1, Math.ceil(reserved.retryAfterSeconds));
    const headers = { "Retry-After": String(retryAfterSeconds) };
    return reserved.reason === "rate"
      ? reply(429, { error: "rate-limited", limit: cfg.rateLimitPerWindow, windowSeconds: cfg.rateWindowSeconds, retryAfterSeconds }, headers)
      : reply(429, { error: "quota-exceeded", quotaBytes: cfg.quotaBytes, windowSeconds: cfg.quotaWindowSeconds, retryAfterSeconds }, headers);
  }
  if (reserved.status === "complete") {
    return reply(200, { captureId: reserved.id, deduped: true, status: "complete" });
  }

  // Pending: hand out the signed upload URL (or point at finalize if the object is already there).
  const path = objectPath(user.id, r.captureId);
  const upload = await deps.createUpload(path);
  const dedupedField = reserved.deduped ? { deduped: true } : {};
  if (upload === "exists") return reply(200, { captureId: reserved.id, status: "pending", ...dedupedField });
  return reply(200, {
    captureId: reserved.id,
    status: "pending",
    ...dedupedField,
    uploadUrl: upload.uploadUrl,
    token: upload.token,
    path,
    bucket: BUCKET,
    expiresIn: SIGNED_UPLOAD_TTL_SECONDS
  });
}

async function finalizeCapture(user: User, rawBody: unknown, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const parsed = parseFinalizeRequest(rawBody);
  if (!parsed.ok) return fail(parsed.status, parsed.error, { message: parsed.message });
  const { rowId } = parsed.value;

  const row = await deps.getCapture(user.id, rowId);
  if (!row) return fail(404, "not-found");
  if (row.status === "complete") return reply(200, { captureId: row.id, status: "complete" });

  // Checks on the stored object — metadata and 2 bytes only; the bundle is never downloaded or parsed here.
  // A rejected object is DELETED right away (not left for the 24 h sweep): the row stays pending, so the client
  // can fix its upload — a repeat reserve finds no object and hands out a fresh signed URL.
  const reject = async (res: Response): Promise<Response> => {
    try {
      await deps.removeObject(row.objectPath);
    } catch (e) {
      console.error("diagnostic-captures: removing a rejected object failed (gc-blobs will sweep it):", e instanceof Error ? e.message : e);
    }
    return res;
  };
  const stat = await deps.statObject(row.objectPath);
  if (!stat) return fail(409, "not-uploaded", { message: "no object has been uploaded for this capture yet" });
  if (stat.size > cfg.maxUploadBytes) return await reject(fail(413, "too-large", { stage: "stored", limit: cfg.maxUploadBytes }));
  // An object larger than announced is refused (smaller is fine; the real size is recorded below).
  if (stat.size > row.bytes) return await reject(fail(409, "size-mismatch", { announced: row.bytes, actual: stat.size }));
  if (stat.size < 2) return await reject(fail(400, "invalid-gzip", { message: "stored object is not a gzip file" }));
  const head = await deps.readHead(row.objectPath, 2);
  if (!head) return fail(409, "not-uploaded", { message: "no object has been uploaded for this capture yet" });
  if (!isGzip(head)) return await reject(fail(400, "invalid-gzip", { message: "stored object is not a gzip file" }));

  const done = await deps.completeCapture(user.id, row.id, stat.size);
  if (!done) {
    // Not pending any more: a concurrent finalize won (fine) or the row was swept in the meantime.
    const again = await deps.getCapture(user.id, row.id);
    if (!again || again.status !== "complete") return fail(404, "not-found");
  }
  return reply(200, { captureId: row.id, status: "complete" });
}
