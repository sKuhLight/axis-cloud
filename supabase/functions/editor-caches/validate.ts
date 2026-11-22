// Constants, request validation, the network key and the editor-cache structure check for the `editor-caches`
// edge function. Deliberately free of Deno globals and `jsr:` imports (web-standard APIs only) so all of it is
// unit-testable without a Supabase stack — see validate.test.ts and handler.test.ts.

// ─────────────────────────────────────────── limits ───────────────────────────────────────────

/** Largest cache file a client may announce/upload. The bucket enforces it too. Real files are ~0.1–0.35 MB. */
export const MAX_UPLOAD_BYTES = 4 * 1024 * 1024;
/** Reserve/finalize/delete requests are a few hundred bytes; anything bigger is not a legitimate client. */
export const MAX_JSON_BODY_BYTES = 8 * 1024;

/** New uploads per uploader per rolling window (pending reservations count). */
export const RATE_LIMIT_PER_WINDOW = 5;
export const RATE_WINDOW_SECONDS = 60 * 60;
/** Bytes per uploader per rolling quota window. An unconfirmed reservation counts at MAX_UPLOAD_BYTES (its
 *  announced size is unverified until finalize), so at most 5 can be outstanding. */
export const QUOTA_BYTES = 20 * 1024 * 1024;
export const QUOTA_WINDOW_SECONDS = 30 * 24 * 60 * 60;
/** The same two limits per client network (keyed hash of the IPv4 address / IPv6 /64). Anonymous uploader ids
 *  cost nothing to mint, so this is the limit that binds a determined abuser. */
export const IP_RATE_LIMIT_PER_WINDOW = 5;
export const IP_QUOTA_BYTES = 20 * 1024 * 1024;
/** Rows per (uploader, model, firmware), pending or complete. */
export const PER_FIRMWARE_MAX = 2;
/** Distinct uploaders with a complete, version-matched upload after which a firmware is "covered". */
export const COVERAGE_THRESHOLD = 2;

/** Lifetime of a storage signed upload URL/token (fixed by Supabase Storage: 2 hours). */
export const SIGNED_UPLOAD_TTL_SECONDS = 2 * 60 * 60;
/** A pending reservation older than this is recreated instead of reused (gc-blobs sweeps pending rows after
 *  24 h; a client must never get an upload URL for a row that sweep is about to delete). */
export const PENDING_REFRESH_MAX_AGE_SECONDS = 20 * 60 * 60;
/** consentAt (client clock) must be within this distance of the server's clock. */
export const CONSENT_SKEW_SECONDS = 24 * 60 * 60;
/** Oldest disclosure text whose consent is accepted. Version 2 is the first text that covers uploads without an
 *  account (anonymous sessions); a consent given to an older text is refused (400 consent-required). */
export const MIN_CONSENT_VERSION = 2;
/** Shortest acceptable EDITOR_CACHE_IP_SALT. A shorter (guessable) secret would let anyone holding a stored
 *  network key test candidate addresses against it, so the function fails closed instead (503 paused). */
export const MIN_IP_SALT_LENGTH = 32;
/** Public status answers may be cached this long (they change rarely: only when a firmware gets covered). */
export const STATUS_MAX_AGE_SECONDS = 600;
/** Most rows the "my uploads" listing returns (an uploader has a handful at most: see the limits above). */
export const LIST_LIMIT = 100;

/**
 * Models whose editor caches have the layout validateEditorCache() checks (a 46-byte header, then sections),
 * i.e. the devices that can contribute: Axe-Fx III (0x10), FM3 (0x11), FM9 (0x12). Anything else is never
 * "wanted" and is refused at reserve time (409 not-wanted).
 */
export const CONTRIBUTE_MODELS: readonly number[] = [0x10, 0x11, 0x12];

export const BUCKET = "editor-caches";
export const CONTENT_TYPE = "application/octet-stream";

// ─────────────────────────────────────────── small helpers ───────────────────────────────────────────

/** Access tokens are JWTs (three base64url parts); anything else is refused without an Auth round trip. */
const JWT_SHAPE_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
export function looksLikeJwt(token: string): boolean {
  return token.length <= 8192 && JWT_SHAPE_RE.test(token);
}

export const FIRMWARE_RE = /^\d{1,3}\.\d{1,3}$/;
/** Generic path-safe file name (also a DB CHECK). */
export const FILE_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$/;
/** The name the official editors give the file: `effectDefinitions_<model hex>_<major>p<minor>.cache`. */
const EDITOR_CACHE_NAME_RE = /^effectDefinitions_([0-9a-fA-F]{1,2})_(\d{1,3})p(\d{1,3})\.cache$/;
export const SHA256_RE = /^[0-9a-f]{64}$/;
const ROW_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SUSPECT_FAMILY_RE = /^[A-Z0-9_]{1,24}$/;

export function objectPath(userId: string, sha256: string): string {
  return `${userId}/${sha256}.cache`;
}

/** `${major}.${minor}` without leading zeros (the form the device and the DB use). */
function versionString(major: number, minor: number): string {
  return `${major}.${minor}`;
}

/** Normalizes a firmware string (`"013.00"` -> `"13.0"`); null when it does not match FIRMWARE_RE. */
export function normalizeFirmware(s: string): string | null {
  if (!FIRMWARE_RE.test(s)) return null;
  const [a, b] = s.split(".");
  return versionString(Number(a), Number(b));
}

/** Model and version encoded in an editor-cache file name; null when the name is not one. */
export function parseEditorCacheName(name: string): { model: number; version: string } | null {
  const m = EDITOR_CACHE_NAME_RE.exec(name);
  if (!m) return null;
  return { model: Number.parseInt(m[1], 16), version: versionString(Number(m[2]), Number(m[3])) };
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // digest() wants an ArrayBuffer-backed view; a view over a SharedArrayBuffer would not type-check.
  const view = bytes.buffer instanceof ArrayBuffer ? (bytes as Uint8Array<ArrayBuffer>) : new Uint8Array(bytes);
  const d = await crypto.subtle.digest("SHA-256", view);
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Reads a request body chunk by chunk and gives up as soon as it exceeds `limit`, so an oversized (or chunked,
 * Content-Length-less) request is never fully buffered. Returns `null` when over the limit.
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

// ─────────────────────────────────────────── network key ───────────────────────────────────────────

/** Default request headers the client address is taken from, in order (see clientNetwork). */
export const DEFAULT_IP_HEADERS: readonly string[] = ["cf-connecting-ip", "x-real-ip", "x-forwarded-for"];

function parseIPv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p <= 255) ? parts : null;
}

/** The eight 16-bit groups of an IPv6 address (with `::` and an embedded IPv4 tail); null if not one. */
function parseIPv6(s: string): number[] | null {
  let str = s.toLowerCase();
  const zone = str.indexOf("%");
  if (zone >= 0) str = str.slice(0, zone);
  let tail: number[] = [];
  const lastColon = str.lastIndexOf(":");
  if (lastColon >= 0 && str.slice(lastColon + 1).includes(".")) {
    const v4 = parseIPv4(str.slice(lastColon + 1));
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    str = str.slice(0, lastColon + 1) + "0:0"; // two placeholder groups (an IPv4 tail fills two), replaced below
  }
  const halves = str.split("::");
  if (halves.length > 2) return null;
  const group = (g: string) => (/^[0-9a-f]{1,4}$/.test(g) ? Number.parseInt(g, 16) : NaN);
  const left = halves[0] ? halves[0].split(":").map(group) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").map(group) : [];
  if ([...left, ...right].some((n) => Number.isNaN(n))) return null;
  let groups: number[];
  if (halves.length === 2) {
    const fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    groups = [...left, ...new Array(fill).fill(0), ...right];
  } else {
    groups = left;
  }
  if (groups.length !== 8) return null;
  if (tail.length) groups = [...groups.slice(0, 6), ...tail];
  return groups;
}

/**
 * The client's NETWORK as a canonical string, used only as HMAC input (never stored or logged):
 * `v4:<a.b.c.d>` for IPv4 (incl. IPv4-mapped IPv6), `v6:<first four groups>` for IPv6 (a /64 is what one
 * subscriber typically gets, so the limits cannot be dodged by rotating the interface id), `unknown` when no
 * header carries a parseable address (all such requests then share one bucket — fail closed, not open).
 *
 * Header trust: `headers` lists the headers to consult, in order. The defaults fit the hosted platform:
 * `cf-connecting-ip` is set by the edge proxy (a client-sent value is overwritten), `x-real-ip` by the API
 * gateway, and of `x-forwarded-for` only the LAST entry is used — the one the nearest proxy appended; earlier
 * entries are whatever the client sent. A self-hosted deployment behind a different proxy can override the list
 * (EDITOR_CACHE_IP_HEADERS) with the header its proxy sets.
 */
export function clientNetwork(headers: Headers, headerOrder: readonly string[] = DEFAULT_IP_HEADERS): string {
  for (const name of headerOrder) {
    const raw = headers.get(name);
    if (!raw) continue;
    const entries = raw.split(",").map((e) => e.trim()).filter(Boolean);
    let candidate = name.toLowerCase() === "x-forwarded-for" ? entries[entries.length - 1] : entries[0];
    if (!candidate) continue;
    // "[v6]:port" / "v4:port"
    const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(candidate);
    if (bracket) candidate = bracket[1];
    else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(candidate)) candidate = candidate.replace(/:\d+$/, "");
    const v4 = parseIPv4(candidate);
    if (v4) return `v4:${v4.join(".")}`;
    const v6 = parseIPv6(candidate);
    if (v6) {
      // IPv4-mapped (::ffff:a.b.c.d) is an IPv4 client.
      if (v6.slice(0, 5).every((g) => g === 0) && v6[5] === 0xffff) {
        return `v4:${v6[6] >> 8}.${v6[6] & 0xff}.${v6[7] >> 8}.${v6[7] & 0xff}`;
      }
      return `v6:${v6.slice(0, 4).map((g) => g.toString(16)).join(":")}`;
    }
  }
  return "unknown";
}

/**
 * Which of the client-address headers a request carries, and how many entries its x-forwarded-for has — NEVER
 * their values. Logged (sampled) so the operator can confirm on the hosted platform which header the proxy sets
 * and then pin EDITOR_CACHE_IP_HEADERS to it.
 */
export function describeClientHeaders(headers: Headers, headerOrder: readonly string[] = DEFAULT_IP_HEADERS): { present: string[]; xffEntries: number } {
  const names = [...new Set([...DEFAULT_IP_HEADERS, ...headerOrder].map((h) => h.toLowerCase()))];
  const present = names.filter((h) => (headers.get(h) ?? "").trim() !== "");
  const xff = headers.get("x-forwarded-for") ?? "";
  return { present, xffEntries: xff.split(",").map((e) => e.trim()).filter(Boolean).length };
}

/** HMAC-SHA256(secret, network) as lowercase hex — the only form in which a network reaches the database. */
export async function networkKey(secret: string, network: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`editor-cache-network:v1:${network}`));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
}

// ─────────────────────────────────────────── request validation ───────────────────────────────────────────

export type Parsed<T> =
  | { ok: true; value: T }
  | { ok: false; status: 400 | 409 | 413; error: string; message: string; limit?: number };

const bad = (message: string, error = "invalid-request"): { ok: false; status: 400; error: string; message: string } =>
  ({ ok: false, status: 400, error, message });

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonNegInt(v: unknown, max: number): number | undefined {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max ? v : undefined;
}

/** What the client announces when reserving an upload (all validated/sanitized, never raw client JSON). */
export interface ReserveRequest {
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
}

const REDACTION_KEYS = ["version", "tables", "names"] as const;

/**
 * The client's redaction record, strictly `{ version, tables, names }`: version an integer ≥ 1, the counts
 * non-negative integers, no other key. null when the shape differs. (Counts only — the server re-checks the
 * redaction itself on the stored bytes at finalize.)
 */
export function parseRedaction(v: unknown): Record<string, number> | null {
  if (!isPlainObject(v)) return null;
  const keys = Object.keys(v);
  if (keys.length !== REDACTION_KEYS.length || !REDACTION_KEYS.every((k) => keys.includes(k))) return null;
  const version = nonNegInt(v.version, 1000);
  const tables = nonNegInt(v.tables, 1_000_000);
  const names = nonNegInt(v.names, 1_000_000);
  if (version === undefined || version < 1 || tables === undefined || names === undefined) return null;
  return { version, tables, names };
}

/** Known numeric keys + `agreement` (0..1) + `suspectFamilies` (≤ 16 short upper-case ids); the rest dropped. */
export function sanitizeSummary(v: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (!isPlainObject(v)) return out;
  for (const k of ["sections", "records", "unmappedSections", "newRows", "incompatibleRows"]) {
    const n = nonNegInt(v[k], 10_000_000);
    if (n !== undefined) out[k] = n;
  }
  if (typeof v.agreement === "number" && Number.isFinite(v.agreement) && v.agreement >= 0 && v.agreement <= 1) {
    out.agreement = v.agreement;
  }
  if (Array.isArray(v.suspectFamilies)) {
    out.suspectFamilies = v.suspectFamilies
      .filter((s): s is string => typeof s === "string" && SUSPECT_FAMILY_RE.test(s))
      .slice(0, 16);
  }
  // Bounded by construction (≈ 0.6 KB at most); the check documents the contract's 2 KB ceiling.
  return JSON.stringify(out).length <= 2048 ? out : {};
}

/** A version stamp: `0.9.0-beta`, `1.2.3+build.4` — never free text (no paths, names or host data). */
const VERSION_STAMP_RE = /^[0-9A-Za-z.+-]{1,32}$/;

/** Version stamps only — forgefx / codec / axis, each version-like; anything else is dropped. */
export function sanitizeApp(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isPlainObject(v)) return out;
  for (const k of ["forgefx", "codec", "axis"]) {
    const s = v[k];
    if (typeof s === "string" && VERSION_STAMP_RE.test(s)) out[k] = s;
  }
  return out;
}

/**
 * Validates the reserve request (see handler.ts for the shape). The file name must be the editor's own name and
 * agree with the claimed model and file version (a renamed file is refused here; finalize then checks the file's
 * header against the same version).
 */
export function parseReserveRequest(b: unknown, nowMs: number, maxUploadBytes = MAX_UPLOAD_BYTES): Parsed<ReserveRequest> {
  if (!isPlainObject(b)) return bad("request body must be a JSON object");
  const model = b.model;
  if (typeof model !== "number" || !Number.isInteger(model) || model < 0 || model > 255) {
    return bad("model must be an integer 0..255");
  }
  const deviceFirmware = typeof b.deviceFirmware === "string" ? normalizeFirmware(b.deviceFirmware) : null;
  if (!deviceFirmware) return bad("deviceFirmware must be a string like 13.0");
  const fileVersion = typeof b.fileVersion === "string" ? normalizeFirmware(b.fileVersion) : null;
  if (!fileVersion) return bad("fileVersion must be a string like 13.0 (the version in the file name)");
  let contentVersion: string | null = null;
  if (b.contentVersion !== null && b.contentVersion !== undefined) {
    contentVersion = typeof b.contentVersion === "string" ? normalizeFirmware(b.contentVersion) : null;
    if (!contentVersion) return bad("contentVersion must be a string like 13.0 or null");
  }
  if (typeof b.fileName !== "string" || !FILE_NAME_RE.test(b.fileName)) {
    return bad("fileName must be the editor's file name");
  }
  const named = parseEditorCacheName(b.fileName);
  if (!named) return bad("fileName is not an editor definitions-cache name");
  if (named.model !== model || named.version !== fileVersion) {
    return bad("fileName does not match model and fileVersion");
  }
  if (typeof b.sha256 !== "string" || !SHA256_RE.test(b.sha256)) {
    return bad("sha256 must be 64 lowercase hex characters (of the bytes to upload)");
  }
  const bytes = b.bytes;
  if (typeof bytes !== "number" || !Number.isInteger(bytes) || bytes < 1) {
    return bad("bytes must be a positive integer (the exact size of the file to upload)");
  }
  if (bytes > maxUploadBytes) {
    return { ok: false, status: 413, error: "too-large", message: `bytes exceeds the ${maxUploadBytes}-byte limit`, limit: maxUploadBytes };
  }
  const redaction = parseRedaction(b.redaction);
  if (!redaction) return bad("redaction must be { version, tables, names } with non-negative integers (version >= 1)");
  // Consent: when it was given (client clock, ±24 h) and which disclosure text was shown.
  if (b.consentAt === undefined || b.consentAt === null || b.consentVersion === undefined || b.consentVersion === null) {
    return bad("consentAt and consentVersion are required", "consent-required");
  }
  const consentMs = typeof b.consentAt === "string" && /^\d{4}-\d{2}-\d{2}T/.test(b.consentAt) ? Date.parse(b.consentAt) : NaN;
  if (!Number.isFinite(consentMs)) return bad("consentAt must be an ISO 8601 timestamp", "consent-required");
  if (Math.abs(consentMs - nowMs) > CONSENT_SKEW_SECONDS * 1000) {
    return bad("consentAt must be within 24 hours of the server time", "consent-required");
  }
  const consentVersion = b.consentVersion;
  if (typeof consentVersion !== "number" || !Number.isInteger(consentVersion) || consentVersion < 1 || consentVersion > 32767) {
    return bad("consentVersion must be an integer 1..32767", "consent-required");
  }
  if (consentVersion < MIN_CONSENT_VERSION) {
    return bad(`consent to disclosure text ${consentVersion} is no longer accepted (minimum ${MIN_CONSENT_VERSION})`, "consent-required");
  }
  return {
    ok: true,
    value: {
      model,
      deviceFirmware,
      fileVersion,
      contentVersion,
      fileName: b.fileName,
      sha256: b.sha256,
      bytes,
      redaction,
      summary: sanitizeSummary(b.summary),
      app: sanitizeApp(b.app),
      consentAt: new Date(consentMs).toISOString(),
      consentVersion
    }
  };
}

/** Finalize and delete name the upload by the row id the reserve call returned (a UUID). */
export function parseUploadIdRequest(b: unknown): Parsed<{ rowId: string }> {
  if (!isPlainObject(b)) return bad("request body must be a JSON object");
  if (typeof b.uploadId !== "string" || !ROW_ID_RE.test(b.uploadId)) {
    return bad("uploadId must be the id returned by the reserve call");
  }
  return { ok: true, value: { rowId: b.uploadId.toLowerCase() } };
}

/** The public status query `?model=<0..255>&firmware=<x.y>`. */
export function parseStatusQuery(q: URLSearchParams): Parsed<{ model: number; firmware: string }> {
  const m = q.get("model") ?? "";
  const f = q.get("firmware") ?? "";
  const model = /^\d{1,3}$/.test(m) ? Number(m) : NaN;
  if (!Number.isInteger(model) || model > 255) return bad("model must be an integer 0..255");
  const firmware = normalizeFirmware(f);
  if (!firmware) return bad("firmware must look like 13.0");
  return { ok: true, value: { model, firmware } };
}

// ─────────────────────────────────────────── editor-cache structure check ───────────────────────────────────────────
//
// The file layout, as observed in the editors' definition caches of the gen-3 devices (and as walked by the
// public forgefx-midi codec, src/cache/records.ts, whose strict-mode rules this mirrors):
//
//   header   46 bytes: u32 LE @0x00 = version major, u32 LE @0x04 = version minor (equal to the version in the
//            file name), u16 @0x08 = 4 in every cache seen, an optional NUL-terminated ASCII build date at
//            0x0a..0x29 (zeros in most files), u32 LE @0x2a = number of sections. Only the version and the
//            section count are checked; unknown header bytes are ignored, as the codec's header reader does.
//   section  u32 tag, u32 recordCount, record × recordCount        (first section at 0x2e, sections to EOF)
//   record   u16 id, u16 typecode, u16 pad (= 0), f32 min, f32 max, f32 default, f32 step, then one of
//              enumTail  := u32 count, count × (u32 len, bytes[len]), u32 x, u16 0
//              tableTail := u32 count, count × (u32 len, bytes[len]), u16 0, u32 idCount, idCount × u32
//                           (ids 0xfff0..0xfffe only: the cab/IR bank tables)
//              floatTail := u32 t1, u32 t2, u16 0                   (a 32-byte record)
//   Name bytes are never control bytes (< 0x20 or 0x7f). An empty name may follow the first entry anywhere, and
//   lead one only in a bank table; an all-empty list is an enum only for a bank table whose id array has one id
//   per name (an unused bank), else the record is float-tailed. Bounds are sanity limits: tags and record
//   counts ≤ 0xffff, names ≤ 255 bytes, ≤ 16384 names per list, ≤ 0xffff ids per table.
//
// USER-NAME TABLES (user content the client must redact) — the codec's isUserNameTable(): id 0xffff (the
// preset-name table), ids 0xfff3..0xfffe (the user/scratchpad cab banks) and ids 0xff00..0xffef (no file seen
// has one; an unknown special table is treated as user names, conservatively). The factory/legacy banks
// 0xfff0..0xfff2 are firmware content and are not checked. Redacted (the codec's isCacheRedacted()) = every name
// in those tables is empty or consists only of '_' (0x5f), the codec's redaction filler; lengths, counts and ids
// are kept, so the file stays byte-identical outside the name spans.
//
// Stricter than the codec on two points, both of which only a damaged or hand-made file can trip: the walk must
// start at 0x2e (gen-3 layout; the codec also accepts the older 0x0e preamble), and the last section must hold as
// many records as its header declares (the codec stops at EOF without checking). Plus a work budget, because an
// edge worker has a hard CPU limit and a crafted file could make the enum/float probing quadratic, and a
// plausibility floor (PLAUSIBILITY_FLOOR), because coverage is decided by two uploads and a structurally valid
// file can be tiny.

/** First section header offset in a gen-3 editor cache = the header size. */
export const CACHE_HEADER_BYTES = 0x2e;
/** Most sections a header may declare (real files: 25–57). */
export const MAX_CACHE_SECTIONS = 1024;
/** The byte the client's redaction writes over every character of a user name. */
export const REDACTED_BYTE = 0x5f;

const MAX_SECTION_TAG = 0xffff;
const MAX_SECTION_RECORDS = 0xffff;
const MAX_NAME_LEN = 255;
const MAX_NAMES = 16384;
const MAX_WIRE_IDS = 0xffff;

/** Records whose names are the user's own: the preset-name table, the user/scratchpad cab banks, and (to be safe)
 *  any unknown special table below the cab banks. Same rule as the codec's isUserNameTable(). */
export function isUserNameTable(id: number): boolean {
  return id === 0xffff || (id >= 0xfff3 && id <= 0xfffe) || (id >= 0xff00 && id <= 0xffef);
}

/**
 * Plausibility floor: what a real device cache has at the very least. Without it two throw-away (anonymous)
 * uploaders could cover any firmware with tiny hand-made files that pass the structure walk. Real caches of the
 * contributing devices are 278–329 KB with 45–57 sections and ~2,500 records, and all carry the preset-name
 * table; the floor stays far below every one of them.
 */
export interface PlausibilityFloor {
  minBytes: number;
  minSections: number;
  minRecords: number;
  /** A record with the preset-name table id (0xffff) must be present (its names redacted or not checked here). */
  requirePresetNameTable: boolean;
}
export const PLAUSIBILITY_FLOOR: PlausibilityFloor = {
  minBytes: 32 * 1024,
  minSections: 16,
  minRecords: 500,
  requirePresetNameTable: true
};

export type CacheRejectReason =
  | "size"              // smaller than a header + one section header, or above the upload cap
  | "implausible"       // structurally fine, but far smaller than any real device cache (PLAUSIBILITY_FLOOR)
  | "header-version"    // the header's version is not a plausible x.y (1..999 . 0..999)
  | "version-mismatch"  // header version != claimed file version (or claimed content version)
  | "section-count"     // the header's section count is implausible or differs from the walk
  | "structure"         // the section/record walk failed
  | "too-complex"       // the walk exceeded its work budget
  | "not-redacted";     // a user-name table carries names that are not blanked

export type CacheCheck =
  | {
    ok: true;
    /** The file's own version from its header (`major.minor`). */
    headerVersion: string;
    sections: number;
    records: number;
    /** User-name tables found and checked. */
    userNameTables: number;
    /** Non-empty (redacted) names in them. */
    userNames: number;
    /** A record with the preset-name table id exists. */
    presetNameTable: boolean;
  }
  | { ok: false; reason: CacheRejectReason; detail: string };

export interface CacheCheckOptions {
  maxBytes?: number;
  /** Byte reads the name probing may spend; default 8 × size + 1 MiB (real files use about 1 × size). */
  budget?: number;
  /** Plausibility floor; default PLAUSIBILITY_FLOOR. `null` checks structure and redaction only (unit tests). */
  floor?: PlausibilityFloor | null;
}

class Reject extends Error {
  constructor(readonly reason: CacheRejectReason, detail: string) {
    super(detail);
  }
}

const hex = (n: number) => "0x" + n.toString(16);

/**
 * Checks that `buf` is a complete gen-3 editor definitions cache whose header version equals the claimed file
 * version (and content version, when one is claimed) and whose user-name tables are redacted. Never throws;
 * never echoes file content (details are offsets and counts only).
 */
export function validateEditorCache(
  buf: Uint8Array,
  claims: { fileVersion: string; contentVersion: string | null },
  opts: CacheCheckOptions = {}
): CacheCheck {
  const N = buf.length;
  const maxBytes = opts.maxBytes ?? MAX_UPLOAD_BYTES;
  if (N < CACHE_HEADER_BYTES + 8) return { ok: false, reason: "size", detail: `file is ${N} bytes, smaller than a cache header` };
  if (N > maxBytes) return { ok: false, reason: "size", detail: `file is ${N} bytes, above the ${maxBytes}-byte limit` };
  const floor = opts.floor === undefined ? PLAUSIBILITY_FLOOR : opts.floor;
  if (floor && N < floor.minBytes) {
    return { ok: false, reason: "implausible", detail: `file is ${N} bytes; a device cache has at least ${floor.minBytes}` };
  }

  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const u16 = (o: number) => dv.getUint16(o, true);
  const u32 = (o: number) => dv.getUint32(o, true);

  // ── header ──
  const major = u32(0);
  const minor = u32(4);
  if (major < 1 || major > 999 || minor > 999) {
    return { ok: false, reason: "header-version", detail: "the header does not carry a plausible version" };
  }
  const headerVersion = versionString(major, minor);
  if (headerVersion !== claims.fileVersion) {
    return { ok: false, reason: "version-mismatch", detail: `header version ${headerVersion} differs from the file version ${claims.fileVersion}` };
  }
  if (claims.contentVersion !== null && headerVersion !== claims.contentVersion) {
    return { ok: false, reason: "version-mismatch", detail: `header version ${headerVersion} differs from the claimed content version ${claims.contentVersion}` };
  }
  const declaredSections = u32(0x2a);
  if (declaredSections < 1 || declaredSections > MAX_CACHE_SECTIONS) {
    return { ok: false, reason: "section-count", detail: `the header declares ${declaredSections} sections` };
  }

  let budget = opts.budget ?? 8 * N + (1 << 20);
  const spend = (n: number) => {
    budget -= n;
    if (budget < 0) throw new Reject("too-complex", "the file took too much work to walk");
  };

  // ── grammar primitives (mirror the codec's strict walk) ──

  /** A length-prefixed name at `off`: [start, len, next] or undefined. */
  const tryName = (off: number, allowEmpty: boolean): [number, number, number] | undefined => {
    spend(4);
    if (off + 4 > N) return undefined;
    const L = u32(off);
    if (L < (allowEmpty ? 0 : 1) || L > MAX_NAME_LEN || off + 4 + L > N) return undefined;
    spend(L);
    for (let i = 0; i < L; i++) {
      const c = buf[off + 4 + i];
      if (c < 0x20 || c === 0x7f) return undefined;
    }
    return [off + 4, L, off + 4 + L];
  };

  /** An enum/table name list at `off`: [count, spans, end] or undefined (then the record is float-tailed). */
  const tryEnumBody = (off: number, isTable: boolean): [number, Array<[number, number]>, number] | undefined => {
    if (off + 4 > N) return undefined;
    const count = u32(off);
    if (count < 1 || count > MAX_NAMES) return undefined;
    let p = off + 4;
    const spans: Array<[number, number]> = [];
    let anyName = false;
    for (let i = 0; i < count; i++) {
      const r = tryName(p, i > 0 || isTable);
      if (r === undefined) return undefined;
      if (r[1] > 0) anyName = true;
      spans.push([r[0], r[1]]);
      p = r[2];
    }
    if (!anyName && !(isTable && p + 6 <= N && u16(p) === 0 && u32(p + 2) === count)) return undefined;
    return [count, spans, p];
  };

  let records = 0;
  let userNameTables = 0;
  let userNames = 0;
  let unredacted = 0;
  let presetNameTable = false;

  /** One record at `off`; returns the offset after it. */
  const readRecord = (off: number): number => {
    const fail = (what: string, at: number) => new Reject("structure", `${what} at ${hex(at)}`);
    if (off + 22 > N) throw fail("record runs past the end", off);
    const id = u16(off);
    if (u16(off + 4) !== 0) throw fail("record padding is not zero", off);
    if (id === 0xffff) presetNameTable = true;
    const isTable = id >= 0xfff0 && id <= 0xfffe;

    const en = tryEnumBody(off + 22, isTable);
    if (en !== undefined) {
      const [, spans, end] = en;
      if (end + 6 > N) throw fail("enum record runs past the end", off);
      let next: number;
      if (isTable) {
        const z = u16(end);
        const cnt = u32(end + 2);
        if (z !== 0 || cnt > MAX_WIRE_IDS) throw fail("bad table tail", end);
        next = end + 6 + 4 * cnt;
        if (next > N) throw fail("table ids run past the end", end);
      } else {
        if (u16(end + 4) !== 0) throw fail("bad enum trailer", end);
        next = end + 6;
      }
      if (isUserNameTable(id)) {
        userNameTables++;
        for (const [start, len] of spans) {
          if (len === 0) continue;
          userNames++;
          for (let i = 0; i < len; i++) {
            if (buf[start + i] !== REDACTED_BYTE) {
              unredacted++;
              break;
            }
          }
        }
      }
      return next;
    }
    if (off + 32 > N) throw fail("record runs past the end", off);
    if (u16(off + 30) !== 0) throw fail("bad float tail", off + 30);
    return off + 32;
  };

  // ── walk ──
  let sections = 0;
  try {
    const A0 = u32(CACHE_HEADER_BYTES);
    const B0 = u32(CACHE_HEADER_BYTES + 4);
    if (A0 < 1 || A0 > MAX_SECTION_TAG || B0 < 1 || B0 > MAX_SECTION_RECORDS) {
      throw new Reject("structure", `no section header at ${hex(CACHE_HEADER_BYTES)}`);
    }
    let off = CACHE_HEADER_BYTES;
    let remaining = 0;
    while (off < N) {
      if (remaining === 0) {
        if (off + 8 > N) throw new Reject("structure", `trailing bytes at ${hex(off)}`);
        const A = u32(off);
        const B = u32(off + 4);
        if (A === 0 && B === 0x8000_0000) throw new Reject("structure", "older cache revision (not supported)");
        if (A > MAX_SECTION_TAG || B > MAX_SECTION_RECORDS) throw new Reject("structure", `bad section header at ${hex(off)}`);
        sections++;
        if (sections > MAX_CACHE_SECTIONS) throw new Reject("section-count", "too many sections");
        remaining = B;
        off += 8;
        continue;
      }
      off = readRecord(off);
      records++;
      remaining--;
    }
    if (remaining !== 0) throw new Reject("structure", `the last section is ${remaining} record(s) short`);
  } catch (e) {
    if (e instanceof Reject) return { ok: false, reason: e.reason, detail: e.message };
    // A DataView read past the end would be a bug in the bounds checks above; refuse rather than crash.
    return { ok: false, reason: "structure", detail: "the walk ran past the end of the file" };
  }

  if (sections !== declaredSections) {
    return { ok: false, reason: "section-count", detail: `the header declares ${declaredSections} sections, the file has ${sections}` };
  }
  if (unredacted > 0) {
    return { ok: false, reason: "not-redacted", detail: `${unredacted} of ${userNames} user names are not redacted` };
  }
  if (floor) {
    if (sections < floor.minSections || records < floor.minRecords) {
      return {
        ok: false,
        reason: "implausible",
        detail: `${sections} sections / ${records} records; a device cache has at least ${floor.minSections} / ${floor.minRecords}`
      };
    }
    if (floor.requirePresetNameTable && !presetNameTable) {
      return { ok: false, reason: "implausible", detail: "the file has no preset-name table" };
    }
  }
  return { ok: true, headerVersion, sections, records, userNameTables, userNames, presetNameTable };
}
