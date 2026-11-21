// Constants and request validation for the `diagnostic-captures` edge function. Deliberately free of Deno
// globals and `jsr:` imports (web-standard APIs only) so it is unit-testable without a Supabase stack — see
// handler.test.ts. The function only ever handles SMALL JSON requests: the gzip bundle itself goes straight
// from the client to storage and is never read, decompressed or parsed here.

/** Largest gzip bundle a client may announce/upload (contract: 25 MB). The bucket enforces it too. */
export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
/** The reserve/finalize requests are a few hundred bytes; anything bigger is not a legitimate client. */
export const MAX_JSON_BODY_BYTES = 8 * 1024;

/** New captures per user per rolling window (pending reservations count). */
export const RATE_LIMIT_PER_WINDOW = 5;
export const RATE_WINDOW_SECONDS = 60 * 60;
/** Announced bytes per user per rolling quota window. */
export const QUOTA_BYTES = 200 * 1024 * 1024;
export const QUOTA_WINDOW_SECONDS = 30 * 24 * 60 * 60;

/** Lifetime of a storage signed upload URL/token (fixed by Supabase Storage: 2 hours). */
export const SIGNED_UPLOAD_TTL_SECONDS = 2 * 60 * 60;

export const BUCKET = "diagnostic-captures";
/** The bundle id becomes part of a storage object name: keep it path-safe (also a DB CHECK). */
export const CAPTURE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const ROW_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function objectPath(userId: string, captureId: string): string {
  return `${userId}/${captureId}.json.gz`;
}

export function isGzip(b: Uint8Array): boolean {
  return b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
}

/**
 * Reads a request body chunk by chunk and gives up as soon as it exceeds `limit`, so an oversized (or
 * chunked, Content-Length-less) request is never fully buffered. Returns `null` when over the limit.
 */
export async function readBodyCapped(body: ReadableStream<Uint8Array> | null, limit: number): Promise<Uint8Array | null> {
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export type Parsed<T> =
  | { ok: true; value: T }
  | { ok: false; status: 400 | 413; error: string; message: string; limit?: number };

const bad = (message: string): { ok: false; status: 400; error: string; message: string } =>
  ({ ok: false, status: 400, error: "invalid-request", message });

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** What the client announces when reserving an upload (all derived/validated, never raw client JSON). */
export interface ReserveRequest {
  /** The bundle's own id (`bundle.id`); unique per user. */
  captureId: string;
  model: number;
  firmware: string | null;
  /** Version stamps only: forgefx / codec / axis, short strings. */
  app: Record<string, string>;
  state: string;
  /** Exact size of the gzip the client is about to upload. */
  bytes: number;
}

/**
 * Validates the reserve request `{ captureId, model, firmware, app?, state?, bytes }`:
 * `captureId` path-safe string, `model` integer 0..255, `firmware` string (max 64) | null,
 * `bytes` integer 1..MAX_UPLOAD_BYTES (413 above). `app` and `state` are tolerant: only known short
 * strings are kept, anything else is dropped / 'unknown'.
 */
export function parseReserveRequest(b: unknown, maxUploadBytes = MAX_UPLOAD_BYTES): Parsed<ReserveRequest> {
  if (!isPlainObject(b)) return bad("request body must be a JSON object");
  if (typeof b.captureId !== "string" || !CAPTURE_ID_RE.test(b.captureId)) {
    return bad("captureId must be a string matching ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$");
  }
  const model = b.model;
  if (typeof model !== "number" || !Number.isInteger(model) || model < 0 || model > 255) {
    return bad("model must be an integer 0..255");
  }
  // firmware: string | null. A missing key (JSON.stringify drops `undefined`) counts as unknown.
  let firmware: string | null = null;
  if (b.firmware !== null && b.firmware !== undefined) {
    if (typeof b.firmware !== "string" || b.firmware.length > 64) {
      return bad("firmware must be a string (max 64 chars) or null");
    }
    firmware = b.firmware.trim() || null;
  }
  const bytes = b.bytes;
  if (typeof bytes !== "number" || !Number.isInteger(bytes) || bytes < 1) {
    return bad("bytes must be a positive integer (the exact size of the gzip to upload)");
  }
  if (bytes > maxUploadBytes) {
    return { ok: false, status: 413, error: "too-large", message: `bytes exceeds the ${maxUploadBytes}-byte limit`, limit: maxUploadBytes };
  }
  // Tolerant on purpose: an unexpected state string must not reject an otherwise valid request.
  const state = typeof b.state === "string" && /^[a-z]{1,16}$/.test(b.state) ? b.state : "unknown";
  // Only the version stamps, each a short string — `app` is never stored as arbitrary client JSON.
  const app: Record<string, string> = {};
  if (isPlainObject(b.app)) {
    for (const k of ["forgefx", "codec", "axis"]) {
      const v = b.app[k];
      if (typeof v === "string" && v.length > 0) app[k] = v.slice(0, 64);
    }
  }
  return { ok: true, value: { captureId: b.captureId, model, firmware, app, state, bytes } };
}

/** Finalize names the capture by the row id the reserve call returned (a UUID). */
export function parseFinalizeRequest(b: unknown): Parsed<{ rowId: string }> {
  if (!isPlainObject(b)) return bad("request body must be a JSON object");
  if (typeof b.captureId !== "string" || !ROW_ID_RE.test(b.captureId)) {
    return bad("captureId must be the id returned by the reserve call");
  }
  return { ok: true, value: { rowId: b.captureId.toLowerCase() } };
}
