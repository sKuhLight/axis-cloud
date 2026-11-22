// Request handling for `editor-caches` (editor definitions-cache contributions; signed-upload flow), with every
// side effect behind `Deps` so the whole flow is testable with in-memory fakes (handler.test.ts). index.ts wires
// the Supabase adapter.
//
// Who may upload: a signed-in account OR a Supabase anonymous session (a per-install anonymous auth user; the id
// is minted by Supabase Auth and is unrelated to any app telemetry id). Both can list and delete their uploads.
// Abuse is bounded by limits per uploader AND per client network (keyed hash, see validate.ts), the `wanted`
// gate, and a server-side check that the stored file really is a redacted editor cache.
//
//  GET   /editor-caches?model=17&firmware=13.0           public, no auth
//     200 { model, firmware, wanted }   Cache-Control: public, max-age=600. Reveals nothing else. wanted is false
//         when uploads are paused/not configured, the model cannot contribute, or the firmware is covered/closed.
//  GET   /editor-caches/mine  (or ?action=mine)           Bearer
//     200 { uploads: [{ uploadId, model, deviceFirmware, fileVersion, contentVersion, versionMatch, fileName,
//                       sha256, bytes, status, createdAt, expiresAt }] }   the caller's own uploads only
//  POST  /editor-caches                                    Bearer — reserve
//       { model, deviceFirmware, fileVersion, contentVersion?, fileName, sha256, bytes, redaction, summary?, app?,
//         consentAt, consentVersion }
//     200 { uploadId, status: 'pending', uploadUrl, token, path, bucket, expiresIn }   then upload the file:
//           storage-js uploadToSignedUrl(path, token, bytes, { contentType: 'application/octet-stream' })
//     200 { uploadId, status: 'complete', deduped: true }         this uploader already sent this file
//     200 { uploadId: null, status: 'complete', deduped: true }   someone else already sent the identical file
//     200 { uploadId, status: 'pending', deduped: true }          reserved before and the object is there: finalize
//     (+ `deduped: true` on a pending answer that refreshed an earlier reservation)
//  POST  /editor-caches/finalize  { uploadId }  (or ?action=finalize)   Bearer
//     200 { uploadId, status: 'complete', covered }   covered = this firmware is no longer collecting
//     Checks: own pending row; object exists; size ≤ announced and ≤ 4 MiB; sha256 of the stored bytes = the
//     announced one; the bytes are a complete editor cache whose header version equals the file version and
//     whose user-name tables are redacted. A failing object is DELETED at once; the row stays pending.
//  POST  /editor-caches/delete  { uploadId }  (or ?action=delete)       Bearer
//     200 { uploadId, deleted: true }   own upload only (else 404): object first, then the row. Works while paused.
//
//  Errors (JSON { error, message?, ... }):
//   400 invalid-request | invalid-json | empty-body | consent-required   401 unauthorized
//   403 account-required (reserve/finalize by an anonymous session while anonymous uploads are switched off;
//       listing and deleting stay open)   404 not-found   405 method-not-allowed
//   409 not-uploaded | size-mismatch | hash-mismatch | not-wanted | firmware-limit
//   413 too-large   422 invalid-cache { reason }   429 rate-limited | quota-exceeded { scope, retryAfterSeconds }
//   503 paused (EDITOR_CACHE_UPLOADS=off, or the network-key secret missing / shorter than 32 chars)   500 internal
import {
  BUCKET,
  clientNetwork,
  CONTRIBUTE_MODELS,
  COVERAGE_THRESHOLD,
  DEFAULT_IP_HEADERS,
  describeClientHeaders,
  IP_QUOTA_BYTES,
  IP_RATE_LIMIT_PER_WINDOW,
  LIST_LIMIT,
  looksLikeJwt,
  MAX_JSON_BODY_BYTES,
  MAX_UPLOAD_BYTES,
  MIN_IP_SALT_LENGTH,
  networkKey,
  objectPath,
  parseReserveRequest,
  parseStatusQuery,
  parseUploadIdRequest,
  PENDING_REFRESH_MAX_AGE_SECONDS,
  PER_FIRMWARE_MAX,
  QUOTA_BYTES,
  QUOTA_WINDOW_SECONDS,
  RATE_LIMIT_PER_WINDOW,
  RATE_WINDOW_SECONDS,
  readBodyCapped,
  sha256Hex,
  SIGNED_UPLOAD_TTL_SECONDS,
  STATUS_MAX_AGE_SECONDS,
  validateEditorCache
} from "./validate.ts";

export type CoverageState = "collecting" | "covered" | "closed";

export interface ReserveArgs {
  userId: string;
  /** HMAC of the client network (validate.ts networkKey) — never the address. */
  ipKey: string;
  model: number;
  deviceFirmware: string;
  fileVersion: string;
  contentVersion: string | null;
  fileName: string;
  sha256: string;
  bytes: number;
  redaction: Record<string, number>;
  summary: Record<string, unknown>;
  app: Record<string, string>;
  consentAt: string;
  consentVersion: number;
  maxPerWindow: number;
  windowSeconds: number;
  quotaBytes: number;
  quotaWindowSeconds: number;
  /** What an unconfirmed (pending) reservation counts against the byte quotas: the full upload cap. */
  pendingChargeBytes: number;
  pendingMaxAgeSeconds: number;
  perFirmwareMax: number;
  ipMaxPerWindow: number;
  ipQuotaBytes: number;
}

export type ReserveResult =
  | { kind: "ok"; id: string | null; status: "pending" | "complete"; deduped: boolean }
  | { kind: "limited"; reason: "rate" | "quota"; scope: "uploader" | "ip"; retryAfterSeconds: number }
  | { kind: "not-wanted" }
  | { kind: "firmware-limit" };

/** The slice of an editor_cache_uploads row the handler needs. */
export interface UploadRecord {
  id: string;
  status: "pending" | "complete";
  /** Announced size while pending, actual size once complete. */
  bytes: number;
  objectPath: string;
  sha256: string;
  model: number;
  deviceFirmware: string;
  fileVersion: string | null;
  contentVersion: string | null;
}

/** One entry of the caller's own listing. */
export interface UploadSummary {
  uploadId: string;
  model: number;
  deviceFirmware: string;
  fileVersion: string | null;
  contentVersion: string | null;
  versionMatch: boolean;
  fileName: string;
  sha256: string;
  bytes: number;
  status: "pending" | "complete";
  createdAt: string;
  expiresAt: string;
}

export interface CompleteArgs {
  userId: string;
  rowId: string;
  bytes: number;
  /** The header version the server read from the stored bytes. */
  contentVersion: string;
  threshold: number;
}

export interface Deps {
  /** Resolve the user from the bearer token (Auth server round trip); null = invalid/expired. */
  authenticate(accessToken: string): Promise<{ id: string; isAnonymous: boolean } | null>;
  /** Coverage state of (model, firmware); null = no row (collecting). */
  coverageState(model: number, firmware: string): Promise<CoverageState | null>;
  /** Atomic dedup + coverage + limits + insert (the SQL function reserve_editor_cache_upload). */
  reserve(args: ReserveArgs): Promise<ReserveResult>;
  /** Signed upload URL for `path` (no overwrite). 'exists' = an object is already at that path. */
  createUpload(path: string): Promise<{ uploadUrl: string; token: string } | "exists">;
  /** The caller's own row by row id; null if absent or not theirs. */
  getUpload(userId: string, rowId: string): Promise<UploadRecord | null>;
  /** Metadata of the stored object without downloading it; null if there is no such object. */
  statObject(path: string): Promise<{ size: number } | null>;
  /** At most `maxBytes` bytes of the object from its start (a bounded read); null if there is no such object. */
  readObject(path: string, maxBytes: number): Promise<Uint8Array | null>;
  /** pending -> complete + coverage (complete_editor_cache_upload); null when the row does not exist. */
  complete(args: CompleteArgs): Promise<{ status: "pending" | "complete"; covered: boolean } | null>;
  /** Delete the stored object (no error if it is already gone). */
  removeObject(path: string): Promise<void>;
  /** Delete the caller's own row; false if there was none. */
  deleteUpload(userId: string, rowId: string): Promise<boolean>;
  /** The caller's own uploads, newest first. */
  listUploads(userId: string, limit: number): Promise<UploadSummary[]>;
}

export interface HandlerConfig {
  /** false when EDITOR_CACHE_UPLOADS=off: status says wanted:false, reserve/finalize answer 503 paused. */
  enabled: boolean;
  /** Anonymous sessions may upload (maintainer decision: yes). false -> 403 account-required for them. */
  allowAnonymous: boolean;
  /** Secret for the network key (EDITOR_CACHE_IP_SALT). Without it uploads are paused (fail closed). */
  ipSalt: string | null;
  /** Request headers the client address is read from, in order (validate.ts clientNetwork). */
  ipHeaders: readonly string[];
  maxUploadBytes: number;
  maxJsonBodyBytes: number;
  rateLimitPerWindow: number;
  rateWindowSeconds: number;
  quotaBytes: number;
  quotaWindowSeconds: number;
  ipRateLimitPerWindow: number;
  ipQuotaBytes: number;
  perFirmwareMax: number;
  coverageThreshold: number;
  pendingMaxAgeSeconds: number;
  contributeModels: readonly number[];
  now: () => number;
  /** Function log (maintainer-only). Never receives addresses, tokens or file content. */
  log: (level: "info" | "warn", message: string) => void;
}

export const DEFAULT_CONFIG: HandlerConfig = {
  enabled: true,
  allowAnonymous: true,
  ipSalt: null,
  ipHeaders: DEFAULT_IP_HEADERS,
  maxUploadBytes: MAX_UPLOAD_BYTES,
  maxJsonBodyBytes: MAX_JSON_BODY_BYTES,
  rateLimitPerWindow: RATE_LIMIT_PER_WINDOW,
  rateWindowSeconds: RATE_WINDOW_SECONDS,
  quotaBytes: QUOTA_BYTES,
  quotaWindowSeconds: QUOTA_WINDOW_SECONDS,
  ipRateLimitPerWindow: IP_RATE_LIMIT_PER_WINDOW,
  ipQuotaBytes: IP_QUOTA_BYTES,
  perFirmwareMax: PER_FIRMWARE_MAX,
  coverageThreshold: COVERAGE_THRESHOLD,
  pendingMaxAgeSeconds: PENDING_REFRESH_MAX_AGE_SECONDS,
  contributeModels: CONTRIBUTE_MODELS,
  now: () => Date.now(),
  log: (level, message) => (level === "warn" ? console.warn(message) : console.log(message))
};

/**
 * Header diagnostic for the network key: the first reservation an isolate serves logs WHICH client-address
 * headers were present and how many x-forwarded-for entries there were — names and a count, never values — so
 * the operator can confirm on the hosted platform which header its proxy sets and pin EDITOR_CACHE_IP_HEADERS.
 * (Once per isolate = sampled: isolates are short-lived.) Exported so tests can reset it.
 */
export const ipDiagnostics = { logged: false };

// Browser clients (supabase-js, or fetch with its headers) also send `apikey` / `x-client-info`: see
// _shared/cors.ts, whose CORS_ALLOW_HEADERS this must equal (cors.test.ts checks it).
const cors: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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

const paused = () => fail(503, "paused", { message: "editor-cache uploads are paused" });

type User = { id: string };

/** Uploads are open when not switched off AND a strong enough network-key secret is configured (fail closed). */
function uploadsOpen(cfg: HandlerConfig): boolean {
  return cfg.enabled && typeof cfg.ipSalt === "string" && cfg.ipSalt.length >= MIN_IP_SALT_LENGTH;
}

/**
 * Authenticates BEFORE any body is read. `uploading` = reserve/finalize: only those are subject to the
 * anonymous switch — listing and deleting stay open to every uploader, so turning anonymous uploads off never
 * strands an earlier anonymous uploader's data (self-delete is an Art. 17 path).
 */
async function authorize(req: Request, deps: Deps, cfg: HandlerConfig, uploading: boolean): Promise<{ user: User } | { res: Response }> {
  const token = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "")?.[1];
  // A malformed token cannot be valid: refuse it without an Auth-server round trip.
  if (!token || !looksLikeJwt(token)) return { res: fail(401, "unauthorized") };
  const user = await deps.authenticate(token);
  if (!user) return { res: fail(401, "unauthorized") };
  if (uploading && user.isAnonymous && !cfg.allowAnonymous) {
    return { res: fail(403, "account-required", { message: "editor-cache uploads currently need a signed-in account" }) };
  }
  return { user: { id: user.id } };
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

function actionOf(url: URL): string | null {
  const last = url.pathname.replace(/\/+$/, "").split("/").pop() ?? "";
  if (last === "finalize" || last === "delete" || last === "mine") return last;
  return url.searchParams.get("action");
}

export async function handleRequest(req: Request, deps: Deps, cfg: HandlerConfig = DEFAULT_CONFIG): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const url = new URL(req.url);
    const action = actionOf(url);

    if (req.method === "GET") {
      if (action === "mine") return await listMine(req, deps, cfg);
      return await status(url, deps, cfg);
    }
    if (req.method !== "POST") return reply(405, { error: "method-not-allowed" }, { Allow: "GET, POST, OPTIONS" });

    // Paused: no new reservations, no new acceptances. Deleting stays possible (GDPR), so it is checked first.
    if (action !== "delete" && !uploadsOpen(cfg)) return paused();

    const auth = await authorize(req, deps, cfg, action !== "delete");
    if ("res" in auth) return auth.res;
    const body = await readJson(req, cfg);
    if ("res" in body) return body.res;

    if (action === "finalize") return await finalizeUpload(auth.user, body.body, deps, cfg);
    if (action === "delete") return await deleteUpload(auth.user, body.body, deps);
    if (action !== null) return fail(404, "not-found");
    return await reserveUpload(req, auth.user, body.body, deps, cfg);
  } catch (e) {
    // Details go to the function log (maintainer-only), never to the client. Never log addresses or bodies.
    console.error("editor-caches:", e instanceof Error ? e.message : e);
    return fail(500, "internal", { message: "request failed; please try again later" });
  }
}

// ── GET: public status ──

async function status(url: URL, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const q = parseStatusQuery(url.searchParams);
  if (!q.ok) return fail(q.status, q.error, { message: q.message });
  const { model, firmware } = q.value;
  let wanted = false;
  if (uploadsOpen(cfg) && cfg.contributeModels.includes(model)) {
    const state = await deps.coverageState(model, firmware);
    wanted = state === null || state === "collecting";
  }
  return reply(200, { model, firmware, wanted }, { "Cache-Control": `public, max-age=${STATUS_MAX_AGE_SECONDS}` });
}

// ── GET /mine: the caller's own uploads ──

async function listMine(req: Request, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const auth = await authorize(req, deps, cfg, false);
  if ("res" in auth) return auth.res;
  const uploads = await deps.listUploads(auth.user.id, LIST_LIMIT);
  return reply(200, { uploads }, { "Cache-Control": "private, no-store" });
}

// ── POST: reserve ──

async function reserveUpload(req: Request, user: User, rawBody: unknown, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const parsed = parseReserveRequest(rawBody, cfg.now(), cfg.maxUploadBytes);
  if (!parsed.ok) {
    return fail(parsed.status, parsed.error, { message: parsed.message, ...(parsed.limit !== undefined ? { limit: parsed.limit } : {}) });
  }
  const r = parsed.value;
  if (!cfg.contributeModels.includes(r.model)) {
    return fail(409, "not-wanted", { message: "uploads are not collected for this model" });
  }

  // The client network only ever leaves this function as a keyed hash. The diagnostics below log header NAMES and
  // an entry count only — never an address.
  if (!ipDiagnostics.logged) {
    ipDiagnostics.logged = true;
    const d = describeClientHeaders(req.headers, cfg.ipHeaders);
    cfg.log("info", `editor-caches: client-address headers present: [${d.present.join(", ")}]; x-forwarded-for entries: ${d.xffEntries}; consulted in order: [${cfg.ipHeaders.join(", ")}]`);
  }
  const network = clientNetwork(req.headers, cfg.ipHeaders);
  if (network === "unknown") {
    const d = describeClientHeaders(req.headers, cfg.ipHeaders);
    cfg.log("warn", `editor-caches: no usable client address (headers present: [${d.present.join(", ")}]); this request is limited in the shared "unknown" network bucket`);
  }
  const ipKey = await networkKey(cfg.ipSalt!, network);

  const reserved = await deps.reserve({
    userId: user.id,
    ipKey,
    model: r.model,
    deviceFirmware: r.deviceFirmware,
    fileVersion: r.fileVersion,
    contentVersion: r.contentVersion,
    fileName: r.fileName,
    sha256: r.sha256,
    bytes: r.bytes,
    redaction: r.redaction,
    summary: r.summary,
    app: r.app,
    consentAt: r.consentAt,
    consentVersion: r.consentVersion,
    maxPerWindow: cfg.rateLimitPerWindow,
    windowSeconds: cfg.rateWindowSeconds,
    quotaBytes: cfg.quotaBytes,
    quotaWindowSeconds: cfg.quotaWindowSeconds,
    pendingChargeBytes: cfg.maxUploadBytes,
    pendingMaxAgeSeconds: cfg.pendingMaxAgeSeconds,
    perFirmwareMax: cfg.perFirmwareMax,
    ipMaxPerWindow: cfg.ipRateLimitPerWindow,
    ipQuotaBytes: cfg.ipQuotaBytes
  });

  if (reserved.kind === "not-wanted") {
    return fail(409, "not-wanted", { message: "this firmware is no longer being collected" });
  }
  if (reserved.kind === "firmware-limit") {
    return fail(409, "firmware-limit", { limit: cfg.perFirmwareMax, message: "too many uploads for this model and firmware" });
  }
  if (reserved.kind === "limited") {
    const retryAfterSeconds = Math.max(1, Math.ceil(reserved.retryAfterSeconds));
    const headers = { "Retry-After": String(retryAfterSeconds) };
    const perIp = reserved.scope === "ip";
    return reserved.reason === "rate"
      ? reply(429, {
        error: "rate-limited",
        scope: reserved.scope,
        limit: perIp ? cfg.ipRateLimitPerWindow : cfg.rateLimitPerWindow,
        windowSeconds: cfg.rateWindowSeconds,
        retryAfterSeconds
      }, headers)
      : reply(429, {
        error: "quota-exceeded",
        scope: reserved.scope,
        quotaBytes: perIp ? cfg.ipQuotaBytes : cfg.quotaBytes,
        windowSeconds: cfg.quotaWindowSeconds,
        retryAfterSeconds
      }, headers);
  }
  if (reserved.status === "complete") {
    return reply(200, { uploadId: reserved.id, status: "complete", deduped: true });
  }

  // Pending: hand out the signed upload URL (or point at finalize if the object is already there).
  const path = objectPath(user.id, r.sha256);
  const upload = await deps.createUpload(path);
  const dedupedField = reserved.deduped ? { deduped: true } : {};
  if (upload === "exists") return reply(200, { uploadId: reserved.id, status: "pending", ...dedupedField });
  return reply(200, {
    uploadId: reserved.id,
    status: "pending",
    ...dedupedField,
    uploadUrl: upload.uploadUrl,
    token: upload.token,
    path,
    bucket: BUCKET,
    expiresIn: SIGNED_UPLOAD_TTL_SECONDS
  });
}

// ── POST /finalize ──

async function finalizeUpload(user: User, rawBody: unknown, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const parsed = parseUploadIdRequest(rawBody);
  if (!parsed.ok) return fail(parsed.status, parsed.error, { message: parsed.message });
  const { rowId } = parsed.value;

  const row = await deps.getUpload(user.id, rowId);
  if (!row) return fail(404, "not-found");
  if (row.status === "complete") {
    const state = await deps.coverageState(row.model, row.deviceFirmware);
    return reply(200, { uploadId: row.id, status: "complete", covered: state !== null && state !== "collecting" });
  }

  // A rejected object is DELETED right away (not left for the 24 h sweep): the row stays pending, so a client
  // that fixes its file can reserve again and upload.
  const reject = async (res: Response): Promise<Response> => {
    try {
      await deps.removeObject(row.objectPath);
    } catch (e) {
      console.error("editor-caches: removing a rejected object failed (gc-blobs will sweep it):", e instanceof Error ? e.message : e);
    }
    return res;
  };
  const notUploaded = () => fail(409, "not-uploaded", { message: "no file has been uploaded for this upload id yet" });

  const stat = await deps.statObject(row.objectPath);
  if (!stat) return notUploaded();
  if (stat.size > cfg.maxUploadBytes) return await reject(fail(413, "too-large", { stage: "stored", limit: cfg.maxUploadBytes }));
  // Larger than announced is refused (smaller is fine; the real size is recorded below).
  if (stat.size > row.bytes) return await reject(fail(409, "size-mismatch", { announced: row.bytes, actual: stat.size }));

  // Bounded read: at most cap + 1 bytes, so a stored object that grew past the cap is detected, never buffered.
  const bytes = await deps.readObject(row.objectPath, cfg.maxUploadBytes + 1);
  if (!bytes) return notUploaded();
  if (bytes.length > cfg.maxUploadBytes) return await reject(fail(413, "too-large", { stage: "stored", limit: cfg.maxUploadBytes }));
  if (bytes.length > row.bytes) return await reject(fail(409, "size-mismatch", { announced: row.bytes, actual: bytes.length }));

  // The announced hash is never trusted: it must equal the hash of what was stored.
  if ((await sha256Hex(bytes)) !== row.sha256) {
    return await reject(fail(409, "hash-mismatch", { message: "the stored file does not match the announced sha256" }));
  }

  const check = validateEditorCache(bytes, { fileVersion: row.fileVersion ?? "", contentVersion: row.contentVersion }, {
    maxBytes: cfg.maxUploadBytes
  });
  if (!check.ok) {
    return await reject(fail(422, "invalid-cache", { reason: check.reason, message: check.detail }));
  }

  const done = await deps.complete({
    userId: user.id,
    rowId: row.id,
    bytes: bytes.length,
    contentVersion: check.headerVersion,
    threshold: cfg.coverageThreshold
  });
  if (!done) return fail(404, "not-found"); // swept or deleted in the meantime
  return reply(200, { uploadId: row.id, status: "complete", covered: done.covered });
}

// ── POST /delete ──

async function deleteUpload(user: User, rawBody: unknown, deps: Deps): Promise<Response> {
  const parsed = parseUploadIdRequest(rawBody);
  if (!parsed.ok) return fail(parsed.status, parsed.error, { message: parsed.message });
  const row = await deps.getUpload(user.id, parsed.value.rowId);
  if (!row) return fail(404, "not-found");
  // Object first: if removing it fails the row stays, so the user can retry (and nothing is left unreferenced).
  await deps.removeObject(row.objectPath);
  await deps.deleteUpload(user.id, row.id);
  return reply(200, { uploadId: row.id, deleted: true });
}
