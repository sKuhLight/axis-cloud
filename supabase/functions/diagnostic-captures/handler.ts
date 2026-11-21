// Request handling for `diagnostic-captures`, with every side effect behind `UploadDeps` so the whole
// flow is testable with in-memory fakes (handler.test.ts). index.ts wires the real Supabase adapter.
//
//   POST  body = gzip of a CaptureBundle JSON (`schema: 1`), `Content-Type: application/gzip`
//         (do NOT set `Content-Encoding: gzip`: intermediaries may transparently decode it, and this
//         function must see — and store — the original gzip bytes)
//   200   { captureId }                     the diagnostic_captures row id (also for an idempotent repeat,
//                                           which adds `deduped: true`)
//   400 { error: 'invalid-gzip' | 'invalid-json' | 'invalid-bundle' | 'empty-body', message }
//   401 { error: 'unauthorized' }
//   413 { error: 'too-large', stage: 'compressed' | 'decompressed', limit }
//   429 { error: 'rate-limited', limit, windowSeconds, retryAfterSeconds }   (+ Retry-After header)
//   405 { error: 'method-not-allowed' }     500 { error: 'internal' }
import {
  type BundleMeta,
  gunzipCapped,
  isGzip,
  MAX_COMPRESSED_BYTES,
  MAX_DECOMPRESSED_BYTES,
  objectPath,
  RATE_LIMIT_PER_HOUR,
  RATE_WINDOW_MS,
  readBodyCapped,
  validateBundle
} from "./bundle.ts";

/** The row inserted into public.diagnostic_captures (id / created_at / expires_at are DB defaults). */
export interface CaptureRow {
  user_id: string;
  capture_id: string;
  model: number;
  firmware: string | null;
  app: Record<string, string>;
  state: string;
  bytes: number;
  object_path: string;
}

export interface UploadDeps {
  /** Resolve the user from the bearer token (Auth server round trip); null = invalid/expired. */
  authenticate(accessToken: string): Promise<{ id: string } | null>;
  /** The caller's existing capture with this bundle id, if any (idempotency). */
  findCapture(userId: string, captureId: string): Promise<{ id: string } | null>;
  /** created_at (ISO) of the caller's newest captures since `sinceIso`, newest first, at most `limit`. */
  recentUploads(userId: string, sinceIso: string, limit: number): Promise<string[]>;
  /** Store the object WITHOUT overwriting. 'exists' = an object is already at that path. */
  putObject(path: string, body: Uint8Array): Promise<"created" | "exists">;
  removeObject(path: string): Promise<void>;
  /** 'conflict' = (user_id, capture_id) already inserted (concurrent identical upload). */
  insertCapture(row: CaptureRow): Promise<{ id: string } | "conflict">;
  now?(): number;
}

export interface HandlerConfig {
  maxCompressedBytes: number;
  maxDecompressedBytes: number;
  rateLimitPerHour: number;
  rateWindowMs: number;
}

export const DEFAULT_CONFIG: HandlerConfig = {
  maxCompressedBytes: MAX_COMPRESSED_BYTES,
  maxDecompressedBytes: MAX_DECOMPRESSED_BYTES,
  rateLimitPerHour: RATE_LIMIT_PER_HOUR,
  rateWindowMs: RATE_WINDOW_MS
};

const cors: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS"
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

export async function handleUpload(
  req: Request,
  deps: UploadDeps,
  cfg: HandlerConfig = DEFAULT_CONFIG
): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return reply(405, { error: "method-not-allowed" }, { Allow: "POST, OPTIONS" });

  const now = deps.now ?? Date.now;

  try {
    // ── Authenticate FIRST, before any body is read. ──
    const token = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "")?.[1];
    if (!token) return fail(401, "unauthorized");
    const user = await deps.authenticate(token);
    if (!user) return fail(401, "unauthorized");

    // ── Size: reject on the declared length, then enforce the cap while streaming (a chunked body or a
    //    lying Content-Length never gets fully buffered). ──
    const tooLarge = (stage: "compressed" | "decompressed", limit: number) =>
      fail(413, "too-large", { stage, limit });
    const declared = Number(req.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > cfg.maxCompressedBytes) {
      return tooLarge("compressed", cfg.maxCompressedBytes);
    }
    const gz = await readBodyCapped(req.body, cfg.maxCompressedBytes);
    if (gz === null) return tooLarge("compressed", cfg.maxCompressedBytes);
    if (gz.length === 0) return fail(400, "empty-body", { message: "request body is empty" });
    if (!isGzip(gz)) {
      return fail(400, "invalid-gzip", { message: "body must be gzip (Content-Type: application/gzip, no Content-Encoding)" });
    }

    // ── Gunzip (output-capped) → JSON → shape. ──
    const unzipped = await gunzipCapped(gz, cfg.maxDecompressedBytes);
    if (!unzipped.ok) {
      return unzipped.reason === "too-large"
        ? tooLarge("decompressed", cfg.maxDecompressedBytes)
        : fail(400, "invalid-gzip", { message: "body is not a valid gzip stream" });
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(unzipped.data));
    } catch {
      return fail(400, "invalid-json", { message: "decompressed body is not valid UTF-8 JSON" });
    }
    const checked = validateBundle(parsed);
    if (!checked.ok) return fail(400, "invalid-bundle", { message: checked.message });
    const meta: BundleMeta = checked.meta;

    // ── Idempotent repeat: the same bundle id from the same user returns the stored row. Checked BEFORE
    //    the rate limit so a retry after a lost response is never throttled. ──
    const existing = await deps.findCapture(user.id, meta.captureId);
    if (existing) return reply(200, { captureId: existing.id, deduped: true });

    // ── Rate limit: at most N NEW captures per user per rolling window. ──
    const since = new Date(now() - cfg.rateWindowMs).toISOString();
    const recent = await deps.recentUploads(user.id, since, cfg.rateLimitPerHour);
    if (recent.length >= cfg.rateLimitPerHour) {
      // The slot frees up when the oldest of the counted uploads leaves the window.
      const oldest = Date.parse(recent[cfg.rateLimitPerHour - 1]);
      const retryAfterSeconds = Math.max(1, Math.ceil((oldest + cfg.rateWindowMs - now()) / 1000));
      return reply(
        429,
        { error: "rate-limited", limit: cfg.rateLimitPerHour, windowSeconds: cfg.rateWindowMs / 1000, retryAfterSeconds },
        { "Retry-After": String(retryAfterSeconds) }
      );
    }

    // ── Store the ORIGINAL gzip bytes, then the metadata row. ──
    const path = objectPath(user.id, meta.captureId);
    const put = await deps.putObject(path, gz);
    let inserted: { id: string } | "conflict";
    try {
      inserted = await deps.insertCapture({
        user_id: user.id,
        capture_id: meta.captureId,
        model: meta.model,
        firmware: meta.firmware,
        app: meta.app,
        state: meta.state,
        bytes: gz.length,
        object_path: path
      });
    } catch (e) {
      // Don't leave an unreferenced object behind (only one WE created; an 'exists' object belongs to an
      // earlier attempt). The gc-blobs sweep also removes orphans if this cleanup fails.
      if (put === "created") await deps.removeObject(path).catch(() => {});
      throw e;
    }
    if (inserted === "conflict") {
      // A concurrent identical upload won the insert race — answer with its row.
      const winner = await deps.findCapture(user.id, meta.captureId);
      if (!winner) throw new Error("capture insert conflict but no existing row");
      return reply(200, { captureId: winner.id, deduped: true });
    }
    return reply(200, { captureId: inserted.id });
  } catch (e) {
    // Details go to the function log (maintainer-only), never to the client.
    console.error("diagnostic-captures:", e instanceof Error ? e.message : e);
    return fail(500, "internal", { message: "upload failed; please try again later" });
  }
}
