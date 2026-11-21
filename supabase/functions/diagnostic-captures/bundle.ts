// Pure helpers for the `diagnostic-captures` edge function: size-capped body reading, size-capped
// gunzip, and bundle validation. Deliberately free of Deno globals and `jsr:` imports (web-standard
// APIs only) so they are unit-testable without a Supabase stack — see handler.test.ts.

/** Hard cap on the compressed upload (contract: 25 MB). Larger bodies are rejected with 413. */
export const MAX_COMPRESSED_BYTES = 25 * 1024 * 1024;
/**
 * Cap on the DEcompressed bundle. The edge runtime has a 256 MB memory limit and the bundle is then
 * decoded + JSON.parsed (several times its text size on the heap), so this stays well under what would
 * OOM the isolate. Real bundles are ~10 MB of text; a larger one is a bug or a gzip bomb.
 */
export const MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024;
/** Feed gzip input to the decompressor in slices this big: the decompressor materialises the whole output
 *  of one input chunk at once, so one huge chunk would defeat the cap (a bomb expands ~1000:1). */
const GUNZIP_INPUT_SLICE = 16 * 1024;

/** Uploads per user per rolling window (new captures only; idempotent re-uploads don't count). */
export const RATE_LIMIT_PER_HOUR = 5;
export const RATE_WINDOW_MS = 60 * 60 * 1000;

export const BUCKET = "diagnostic-captures";
/** The bundle id becomes part of a storage object name: keep it path-safe (also a DB CHECK). */
export const CAPTURE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function objectPath(userId: string, captureId: string): string {
  return `${userId}/${captureId}.json.gz`;
}

export function isGzip(b: Uint8Array): boolean {
  return b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
}

function concat(chunks: Uint8Array[], total: number): Uint8Array {
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/**
 * Reads a request body chunk by chunk and gives up as soon as it exceeds `limit`, so an oversized (or
 * chunked, Content-Length-less) upload is never fully buffered. Returns `null` when over the limit.
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
  return concat(chunks, total);
}

export type GunzipResult =
  | { ok: true; data: Uint8Array }
  | { ok: false; reason: "too-large" | "invalid" };

/** Gunzips with an output cap. `invalid` = not a well-formed gzip stream; `too-large` = exceeds `limit`. */
export async function gunzipCapped(gz: Uint8Array, limit: number): Promise<GunzipResult> {
  let offset = 0;
  const source = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= gz.length) {
        controller.close();
        return;
      }
      controller.enqueue(gz.subarray(offset, offset + GUNZIP_INPUT_SLICE));
      offset += GUNZIP_INPUT_SLICE;
    }
  });
  // The cast only papers over lib typings that differ between TS/Deno versions (BufferSource vs Uint8Array
  // on the writable side); at runtime this is a plain byte transform.
  const gunzip = new DecompressionStream("gzip") as unknown as ReadableWritablePair<Uint8Array, Uint8Array>;
  const reader = source.pipeThrough(gunzip).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel().catch(() => {});
        return { ok: false, reason: "too-large" };
      }
      chunks.push(value);
    }
  } catch {
    return { ok: false, reason: "invalid" };
  }
  return { ok: true, data: concat(chunks, total) };
}

/** The metadata persisted next to the object (all derived/validated, never raw client JSON). */
export interface BundleMeta {
  captureId: string;
  model: number;
  firmware: string | null;
  state: string;
  app: Record<string, string>;
}

export type ValidateResult = { ok: true; meta: BundleMeta } | { ok: false; message: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validates the shape the contract requires — `schema === 1`, `id`, `device.model` (int),
 * `device.firmware` (string | null), `steps` (array) — and extracts the metadata columns. Everything else
 * in the bundle is stored verbatim inside the gzip object and never interpreted here.
 */
export function validateBundle(b: unknown): ValidateResult {
  if (!isPlainObject(b)) return { ok: false, message: "bundle must be a JSON object" };
  if (b.schema !== 1) return { ok: false, message: "bundle.schema must be 1" };
  if (typeof b.id !== "string" || !CAPTURE_ID_RE.test(b.id)) {
    return { ok: false, message: "bundle.id must be a string matching ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" };
  }
  const device = b.device;
  if (!isPlainObject(device)) return { ok: false, message: "bundle.device must be an object" };
  const model = device.model;
  if (typeof model !== "number" || !Number.isInteger(model) || model < 0 || model > 255) {
    return { ok: false, message: "bundle.device.model must be an integer 0..255" };
  }
  // firmware: string | null. A missing key (JSON.stringify drops `undefined`) counts as unknown.
  let firmware: string | null = null;
  if (device.firmware !== null && device.firmware !== undefined) {
    if (typeof device.firmware !== "string" || device.firmware.length > 64) {
      return { ok: false, message: "bundle.device.firmware must be a string (max 64 chars) or null" };
    }
    firmware = device.firmware.trim() || null;
  }
  if (!Array.isArray(b.steps) || b.steps.length > 64 || !b.steps.every(isPlainObject)) {
    return { ok: false, message: "bundle.steps must be an array (max 64) of objects" };
  }
  // Tolerant on purpose: an unexpected state string must not reject an otherwise valid bundle.
  const state = typeof b.state === "string" && /^[a-z]{1,16}$/.test(b.state) ? b.state : "unknown";
  // Only the version stamps, each a short string — `app` is never stored as arbitrary client JSON.
  const app: Record<string, string> = {};
  if (isPlainObject(b.app)) {
    for (const k of ["forgefx", "codec", "axis"]) {
      const v = b.app[k];
      if (typeof v === "string" && v.length > 0) app[k] = v.slice(0, 64);
    }
  }
  return { ok: true, meta: { captureId: b.id, model, firmware, state, app } };
}
