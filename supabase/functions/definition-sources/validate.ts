// Constants, request parsing and the shared-source validator of the `definition-sources` edge function. Web-standard
// APIs only (no Deno globals, no `jsr:` imports), so all of it is unit-testable without a Supabase stack
// (validate.test.ts).
//
// A contribution carries ONE raw definition source (the public forgefx-midi codec's `RawSource` after its
// `shareableSource` sanitizer). Nothing in it is trusted: the server re-runs the codec's sharing rules on its own,
// field by field, and keeps a SANITIZED COPY built from the known fields only (unknown keys are dropped, never
// stored), in the codec's field order, so what is stored and served is exactly what was checked. The order of the
// checks, and what each answers:
//   1. envelope { model, firmware, kind, rawFormat, source, app, consentAt, consentVersion }
//        400 invalid-request / 409 unsupported-model / 422 unsupported-raw-format / 400 consent-required
//   2. unsafe values anywhere in `source` (depth, `__proto__`/`constructor`/`prototype` keys, non-finite numbers,
//      oversize strings/arrays/objects)                                         422 invalid-source { path, reason }
//   3. privacy: a tolerant parse (`issues`)                                      422 tolerant-source
//               a user name table record (preset names, user cab banks)          422 contains-user-data
//   4. shape: every field typed and bounded, kind <-> space, records inside the declared sections / walked blocks,
//      label rules, a (section, id) repeated with different content            422 invalid-source { path, reason }
//   5. consistency: source firmware = envelope firmware                          422 firmware-inconsistent
//      editor cache: header present, section count and record sums agree        422 invalid-source
//                    file name version null or the header's                     422 version-mismatch
//   6. plausibility floor over what the source SAYS: distinct (section, id) positions and the sections / blocks
//      that carry records (identical repeats and empty declared blocks do not count) 422 implausible
// Stripped on the way (never stored): `id`, `origin`, `contentSha256` (a per-install fingerprint of the redacted
// file), `walk.abortReason` (free text), `capturedAt` precision (coarsened to the UTC day), unknown keys.
// Errors name a path and a rule, never a value from the source.
import {
  CANONICAL_VERSION_RE,
  conflictingDuplicate,
  type FactKind,
  recordSections,
  TAPER_SHAPES,
  uniquePositions,
  UNIT_RE
} from "./facts.ts";

// ─────────────────────────────────────────── limits ───────────────────────────────────────────

/** Largest contribution request (the JSON text). A raw editor-cache source is ~0.43 MB, a live source smaller. */
export const MAX_CONTRIBUTION_BYTES = 2 * 1024 * 1024;
/** Withdraw / report requests are a few hundred bytes. */
export const MAX_JSON_BODY_BYTES = 8 * 1024;

/** New contributions per uploader per rolling window, and per client network (keyed hash). */
export const RATE_LIMIT_PER_WINDOW = 10;
export const NET_RATE_LIMIT_PER_WINDOW = 10;
export const RATE_WINDOW_SECONDS = 60 * 60;
/** Canonical source bytes per uploader and per network per rolling 30 days. */
export const QUOTA_BYTES = 40 * 1024 * 1024;
export const NET_QUOTA_BYTES = 40 * 1024 * 1024;
export const QUOTA_WINDOW_SECONDS = 30 * 24 * 60 * 60;
/** Spot-check reports per uploader and per network per rolling hour. */
export const REPORT_RATE_LIMIT_PER_WINDOW = 30;
export const NET_REPORT_RATE_LIMIT_PER_WINDOW = 30;
export const REPORT_WINDOW_SECONDS = 60 * 60;

/** consentAt (client clock) must be within this distance of the server's clock. */
export const CONSENT_SKEW_SECONDS = 24 * 60 * 60;
/** Oldest share-consent text accepted (shareConsentVersion; any change of meaning bumps it). */
export const MIN_SHARE_CONSENT_VERSION = 1;
/** Shortest acceptable DEFINITION_SOURCES_IP_SALT (a guessable secret would let a key be tested against addresses). */
export const MIN_IP_SALT_LENGTH = 32;
/**
 * The network-key secret this store may use: DEFINITION_SOURCES_IP_SALT when it is at least MIN_IP_SALT_LENGTH
 * characters AND differs from EDITOR_CACHE_IP_SALT (a shared secret would make this public store's markers
 * comparable with the private editor-cache store's). Otherwise null with the reason: writes stay paused.
 */
export function resolveIpSalt(own: string | null | undefined, editorCacheSalt: string | null | undefined): { salt: string | null; problem: "missing" | "short" | "shared" | null } {
  const salt = own ?? "";
  if (salt === "") return { salt: null, problem: "missing" };
  if (salt.length < MIN_IP_SALT_LENGTH) return { salt: null, problem: "short" };
  if (typeof editorCacheSalt === "string" && editorCacheSalt.trim() !== "" && editorCacheSalt.trim() === salt.trim()) {
    return { salt: null, problem: "shared" };
  }
  return { salt, problem: null };
}

/** HMAC domain of this store's network keys (its own secret too: never comparable with the editor-cache keys). */
export const NETWORK_DOMAIN = "definition-source-network:v1";

/** Cache lifetimes of the public answers. A source body never changes for its id (its tier is in the listing). */
export const LIST_MAX_AGE_SECONDS = 300;
export const SOURCE_MAX_AGE_SECONDS = 86400;
/** Most rows GET /mine returns (one vote per uploader, model, firmware and kind keeps it small). */
export const MINE_LIMIT = 100;

/** Devices whose definition sources are collected: Axe-Fx III (0x10), FM3 (0x11), FM9 (0x12). */
export const CONTRIBUTE_MODELS: readonly number[] = [0x10, 0x11, 0x12];
/** Raw envelope formats this validator understands (the codec's RAW_FORMAT). A new format needs this file first. */
export const RAW_FORMATS: readonly number[] = [1];
export const RAW_FORMAT_MAX = Math.max(...RAW_FORMATS);
/** Kinds that may be shared (`live-probe` sources are not, M5). */
export const SHARED_KINDS: readonly FactKind[] = ["editor-cache", "live-readonly", "live-full"];

/** The codec's version stamp: a semantic version (`0.12.0`, `0.12.0-beta.1`, `1.0.0+build.5`), ≤ 64 characters. */
export const CODEC_VERSION_RE =
  /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

/** Size and range bounds of a shared source (plausibility bounds a few times above real data, never below it). */
export const SOURCE_LIMITS = Object.freeze({
  /** Nesting depth below `source` (a source is ~6 deep). */
  depth: 32,
  /** Values in one source (a 2 MiB body cannot hold many more). */
  nodes: 2_000_000,
  /** Characters of any string. */
  string: 65_536,
  /** Length of any array (the longest legitimate one: a bank table's wire ids, ≤ 0xffff). */
  array: 65_536,
  /** Keys of any object / characters of a key. */
  keys: 4_096,
  keyLength: 256,
  /** Records of one source (an FM3 editor cache has ~2.5 k, a live read ~3 k). */
  records: 20_000,
  /** Labels of one enum record (the biggest real roster has ~340) and the UTF-8 bytes of one label. */
  enumValues: 4_096,
  labelBytes: 255,
  /** Wire ids of one bank table. */
  wireIds: 0xffff,
  taperPoints: 1_024,
  /** Sections of an editor cache (real: 25–57). */
  sections: 1_024,
  /** Blocks of a live read: block addresses 0..255, at most 256 of them. */
  maxBlock: 255,
  /** Highest default / per-block param id a live walk may query, ids per explicit list, a live param id. */
  maxParamId: 511,
  idList: 256,
  liveParamId: 16_383,
  boundHits: 4_096,
  codecVersion: 64,
  /** Magnitude of a float field (the largest f32). */
  float: 3.5e38
});

/**
 * Plausibility floor: what a real read of a contributing device has at the very least (real editor caches:
 * 45–57 sections, ~2,500 records; a complete live read: 60+ blocks, ~3,000 records). Without it a few throw-away
 * anonymous sessions could publish (and confirm) tiny hand-made sources. Counted over distinct (section, id)
 * positions and over the sections / blocks that carry records — never the raw record count (identical repeats are
 * allowed and collapse) or the self-declared section list / scope.blocks.
 */
export interface PlausibilityFloor {
  editorCache: { sections: number; records: number };
  live: { blocks: number; records: number };
}
export const PLAUSIBILITY_FLOOR: PlausibilityFloor = {
  editorCache: { sections: 16, records: 500 },
  live: { blocks: 20, records: 300 }
};

// ─────────────────────────────────────────── small helpers ───────────────────────────────────────────

/** Access tokens are JWTs (three base64url parts); anything else is refused without an Auth round trip. */
const JWT_SHAPE_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
export function looksLikeJwt(token: string): boolean {
  return token.length <= 8192 && JWT_SHAPE_RE.test(token);
}

const ROW_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** A row id (UUID), lower-cased; null when it is not one. */
export function parseRowId(v: unknown): string | null {
  return typeof v === "string" && ROW_ID_RE.test(v) ? v.toLowerCase() : null;
}

/** Firmware as the store keys it: canonical `<major>.<minor>` (no leading zeros). */
export function isCanonicalFirmware(v: unknown): v is string {
  return typeof v === "string" && CANONICAL_VERSION_RE.test(v);
}

/** A loose firmware spelling (`013.00`) in canonical form; null when it is not `<1-3 digits>.<1-3 digits>`.
 *  For lookups only — a contribution must already be canonical. */
export function normalizeFirmware(s: string): string | null {
  const m = /^(\d{1,3})\.(\d{1,3})$/.exec(s);
  return m ? `${Number(m[1])}.${Number(m[2])}` : null;
}

/** Records whose names are the user's own: the preset-name table, the user/scratchpad cab banks, and (to be safe)
 *  any unknown special table below the cab banks. The codec's isUserNameTable(). */
export function isUserNameTable(id: number): boolean {
  return id === 0xffff || (id >= 0xfff3 && id <= 0xfffe) || (id >= 0xff00 && id <= 0xffef);
}

/** The cab/IR bank tables (0xfff0..0xfffe): the only records that carry wire ids. */
export function isBankTable(id: number): boolean {
  return id >= 0xfff0 && id <= 0xfffe;
}

/**
 * Reads a request body chunk by chunk and gives up as soon as it exceeds `limit`, so an oversized (or chunked,
 * Content-Length-less) request is never fully buffered. `{ over: n }` when over the limit (n = bytes read when it
 * stopped, a lower bound of the real size).
 */
export async function readBodyCapped(body: ReadableStream<Uint8Array> | null, limit: number): Promise<Uint8Array | { over: number }> {
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
      return { over: total };
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

/** A version stamp: `0.9.0-beta`, `1.2.3+build.4` — never free text (no paths, names or host data). */
const VERSION_STAMP_RE = /^[0-9A-Za-z.+-]{1,32}$/;

/** Version stamps only — forgefx / codec / axis, each version-like; anything else is dropped. */
export function sanitizeApp(v: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!isPlain(v)) return out;
  for (const k of ["forgefx", "codec", "axis"]) {
    const s = v[k];
    if (typeof s === "string" && VERSION_STAMP_RE.test(s)) out[k] = s;
  }
  return out;
}

function isPlain(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

// ─────────────────────────────────────────── capturedAt ───────────────────────────────────────────
// The codec's coarsenCapturedAt (share.ts), ported: the UTC day of an ISO stamp as `YYYY-MM-DDT00:00:00.000Z`;
// a stamp without an offset, an impossible date or free text gives null (nothing is guessed or passed on).

const ISO_STAMP = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2}))?$/;
const DAY_MS = 86_400_000;

function daysIn(year: number, month: number): number {
  if (month === 2) return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28;
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

export function coarsenCapturedAt(stamp: unknown): string | null {
  if (typeof stamp !== "string") return null;
  const m = ISO_STAMP.exec(stamp);
  if (m === null) return null;
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = m[4] === undefined ? 0 : Number(m[4]);
  const minute = m[5] === undefined ? 0 : Number(m[5]);
  const second = m[6] === undefined ? 0 : Number(m[6]);
  if (month < 1 || month > 12 || day < 1 || day > daysIn(year, month)) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;
  let offsetMin = 0;
  const tz = m[7];
  if (tz !== undefined && tz !== "Z") {
    const oh = Number(tz.slice(1, 3));
    const om = Number(tz.slice(4, 6));
    if (oh > 23 || om > 59) return null;
    offsetMin = (tz[0] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const d = new Date(0);
  d.setUTCFullYear(year, month - 1, day);
  d.setUTCHours(hour, minute, second, 0);
  const utc = d.getTime() - offsetMin * 60_000;
  const iso = new Date(Math.floor(utc / DAY_MS) * DAY_MS).toISOString();
  return /^\d{4}-\d{2}-\d{2}T00:00:00\.000Z$/.test(iso) ? iso : null;
}

// ─────────────────────────────────────────── results ───────────────────────────────────────────

export interface Refusal {
  ok: false;
  status: 400 | 404 | 409 | 413 | 422;
  error: string;
  /** Extra response fields (`message`, `path` + `reason`, counts). Never a value from the source. */
  fields: Record<string, unknown>;
}
export type Parsed<T> = { ok: true; value: T } | Refusal;

const refuse = (status: Refusal["status"], error: string, fields: Record<string, unknown> = {}): Refusal =>
  ({ ok: false, status, error, fields });
const badRequest = (message: string, error = "invalid-request") => refuse(400, error, { message });

class Refused extends Error {
  constructor(readonly refusal: Refusal) {
    super(refusal.error);
  }
}
/** 422 invalid-source at `path` (a field path, never a value). */
const invalid = (path: string, reason: string): never => {
  throw new Refused(refuse(422, "invalid-source", { path, reason }));
};

// ─────────────────────────────────────────── stage 2: unsafe values ───────────────────────────────────────────

const FORBIDDEN_KEYS: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);

/** A path segment for a key: a short identifier or number as is, anything else masked (never echoes free text). */
function keySegment(k: string): string {
  if (/^[A-Za-z_$][\w$]{0,63}$/.test(k)) return `.${k}`;
  if (/^\d{1,6}$/.test(k)) return `["${k}"]`;
  return "[?]";
}

/**
 * Is `root` plain, bounded JSON data? null when it is, else { path, reason } of the first problem. Bounded
 * recursion (depth checked before descending), so a deeply nested value cannot exhaust the stack.
 */
export function findUnsafeValue(root: unknown, rootPath = "source"): { path: string; reason: string } | null {
  const trail: string[] = [];
  let nodes = 0;
  const fail = (reason: string) => ({ path: rootPath + trail.join(""), reason });
  const visit = (v: unknown, depth: number): { path: string; reason: string } | null => {
    if (++nodes > SOURCE_LIMITS.nodes) return fail("too many values");
    if (v === null || typeof v === "boolean") return null;
    if (typeof v === "number") return Number.isFinite(v) ? null : fail("not a finite number");
    if (typeof v === "string") return v.length <= SOURCE_LIMITS.string ? null : fail(`string longer than ${SOURCE_LIMITS.string} characters`);
    if (typeof v !== "object") return fail(`not JSON data (${typeof v})`);
    if (depth >= SOURCE_LIMITS.depth) return fail(`nested deeper than ${SOURCE_LIMITS.depth} levels`);
    if (Array.isArray(v)) {
      if (v.length > SOURCE_LIMITS.array) return fail(`array longer than ${SOURCE_LIMITS.array}`);
      for (let i = 0; i < v.length; i++) {
        trail.push(`[${i}]`);
        const r = visit(v[i], depth + 1);
        trail.pop();
        if (r) return r;
      }
      return null;
    }
    if (!isPlain(v)) return fail("not a plain object");
    const keys = Object.keys(v);
    if (keys.length > SOURCE_LIMITS.keys) return fail(`object with more than ${SOURCE_LIMITS.keys} keys`);
    for (const k of keys) {
      trail.push(keySegment(k));
      if (FORBIDDEN_KEYS.has(k)) return fail("forbidden key");
      if (k.length > SOURCE_LIMITS.keyLength) return fail("key too long");
      const r = visit(v[k], depth + 1);
      trail.pop();
      if (r) return r;
    }
    return null;
  };
  return visit(root, 0);
}

// ─────────────────────────────────────────── stage 4: shape (the sanitized copy) ───────────────────────────────────────────

export interface SharedTaper {
  shape: (typeof TAPER_SHAPES)[number];
  err: number | null;
  reliable: boolean;
  points: Array<[number, number]>;
}
export interface SharedFloatRecord {
  kind: "float";
  section: number;
  id: number;
  tc: number;
  min: number;
  max: number;
  def: number;
  step: number;
  unit?: string;
  t1: number;
  t2: number;
  taper?: SharedTaper;
  placeholder?: true;
}
export interface SharedEnumRecord {
  kind: "enum";
  section: number;
  id: number;
  tc: number;
  min: number;
  max: number;
  def: number;
  step: number;
  unit?: string;
  count: number;
  values: string[];
  x: number;
  wireIds?: number[];
}
export type SharedRecord = SharedFloatRecord | SharedEnumRecord;

/** An editor-cache source as stored and served (the codec's ShareableEditorCacheSource). */
export interface SharedEditorCacheSource {
  kind: "editor-cache";
  space: "section";
  capturedAt: string | null;
  firmware: string | null;
  codecVersion: string;
  sections: Array<{ tag: number; count: number }>;
  omitted: { tables: number; records: number };
  header: { major: number; minor: number; sectionCount: number } | null;
  fileVersion: string | null;
  contentSha256: null;
  records: SharedRecord[];
}
export interface SharedLiveScope {
  blocks: number[];
  maxParamId: number;
  bounds: Record<number, number>;
  idLists?: Record<number, number[]>;
  extended: boolean;
  above160: boolean;
  hinted: boolean;
}
export interface SharedLiveWalk {
  queries: number;
  lostReplies: number;
  recoveredReplies: number;
  unresolvedReplies: number;
  placeholderSlots: number;
  missingSlots: number;
  silentAddresses: number;
  pseudoReplies?: { endMarker: number; duplicateId: number; implausible: number };
  boundHits: Array<{ block: number; lastReal: number; bound: number }>;
  extension?: "done" | "skipped" | "aborted";
}
/** A live source as stored and served (the codec's ShareableLiveSource: no `walk.abortReason`). */
export interface SharedLiveSource {
  kind: "live-readonly" | "live-full";
  space: "block";
  capturedAt: string | null;
  firmware: string | null;
  codecVersion: string;
  scope: SharedLiveScope;
  walk: SharedLiveWalk;
  records: SharedRecord[];
}
export type SharedSource = SharedEditorCacheSource | SharedLiveSource;

const U16 = 0xffff;
const U32 = 0xffffffff;

const obj = (v: unknown, path: string): Record<string, unknown> => (isPlain(v) ? v : invalid(path, "expected an object"));
const arr = (v: unknown, path: string, max: number): unknown[] => {
  if (!Array.isArray(v)) return invalid(path, "expected an array");
  return v.length <= max ? v : invalid(path, `array longer than ${max}`);
};
const int = (v: unknown, path: string, max: number): number =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max ? (v === 0 ? 0 : v) : invalid(path, `expected an integer 0..${max}`);
const flt = (v: unknown, path: string): number =>
  typeof v === "number" && Number.isFinite(v) && Math.abs(v) <= SOURCE_LIMITS.float ? (v === 0 ? 0 : v) : invalid(path, "expected a finite number");
const bool = (v: unknown, path: string): boolean => (typeof v === "boolean" ? v : invalid(path, "expected a boolean"));
function oneOf<T extends string>(v: unknown, path: string, set: readonly T[]): T {
  return typeof v === "string" && (set as readonly string[]).includes(v) ? (v as T) : invalid(path, `expected one of ${set.join(" | ")}`);
}
const versionOrNull = (v: unknown, path: string): string | null =>
  v === null ? null : isCanonicalFirmware(v) ? v : invalid(path, 'expected null or "<major>.<minor>" without leading zeros');

/**
 * A label (enum value, roster entry, cab name): at most 255 UTF-8 bytes (the editor file's name limit), no C0
 * control character or DEL (never part of a name in the file or a device reply), no lone surrogate.
 */
export function isValidLabel(s: string): boolean {
  let bytes = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return false;
    if (c < 0x80) bytes += 1;
    else if (c < 0x800) bytes += 2;
    else if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      bytes += 4;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
    else bytes += 3;
    if (bytes > SOURCE_LIMITS.labelBytes) return false;
  }
  return true;
}

function taper(v: unknown, path: string): SharedTaper {
  const o = obj(v, path);
  const shape = oneOf(o.shape, `${path}.shape`, TAPER_SHAPES);
  const err = o.err === null ? null : flt(o.err, `${path}.err`);
  const reliable = bool(o.reliable, `${path}.reliable`);
  const points = arr(o.points, `${path}.points`, SOURCE_LIMITS.taperPoints).map((p, i): [number, number] => {
    const pair = arr(p, `${path}.points[${i}]`, 2);
    if (pair.length !== 2) invalid(`${path}.points[${i}]`, "expected a [normalized, display] pair");
    return [flt(pair[0], `${path}.points[${i}][0]`), flt(pair[1], `${path}.points[${i}][1]`)];
  });
  return { shape, err, reliable, points };
}

/** One record, checked and copied (fields in the codec's order). */
function record(v: unknown, path: string, live: boolean, accept: (section: number) => boolean): SharedRecord {
  const o = obj(v, path);
  const kind = oneOf(o.kind, `${path}.kind`, ["float", "enum"] as const);
  const section = int(o.section, `${path}.section`, live ? SOURCE_LIMITS.maxBlock : U16);
  if (!accept(section)) invalid(`${path}.section`, live ? "not a block this source walked (scope.blocks)" : "not a section this source declares");
  const id = int(o.id, `${path}.id`, live ? SOURCE_LIMITS.liveParamId : U16);
  const tc = int(o.tc, `${path}.tc`, U16);
  const min = flt(o.min, `${path}.min`);
  const max = flt(o.max, `${path}.max`);
  const def = flt(o.def, `${path}.def`);
  const step = flt(o.step, `${path}.step`);
  let unit: string | undefined;
  if (o.unit !== undefined) {
    if (typeof o.unit !== "string" || !UNIT_RE.test(o.unit)) invalid(`${path}.unit`, "expected a unit token");
    unit = o.unit as string;
  }
  if (kind === "float") {
    const t1 = int(o.t1, `${path}.t1`, U32);
    const t2 = int(o.t2, `${path}.t2`, U32);
    const tp = o.taper === undefined ? undefined : taper(o.taper, `${path}.taper`);
    const placeholder = o.placeholder === undefined ? undefined : bool(o.placeholder, `${path}.placeholder`);
    return {
      kind: "float",
      section,
      id,
      tc,
      min,
      max,
      def,
      step,
      ...(unit !== undefined ? { unit } : {}),
      t1,
      t2,
      ...(tp !== undefined ? { taper: tp } : {}),
      ...(placeholder === true ? { placeholder: true as const } : {})
    };
  }
  const values = arr(o.values, `${path}.values`, SOURCE_LIMITS.enumValues).map((s, i) =>
    typeof s === "string" && isValidLabel(s) ? s : invalid(`${path}.values[${i}]`, `expected a label of at most ${SOURCE_LIMITS.labelBytes} bytes without control characters`)
  );
  const count = int(o.count, `${path}.count`, U32);
  // An editor-cache enum IS its name list (u32 count, then the names). A live enum's count comes from the
  // definition's range and its labels from a separate (possibly partial) label walk, so they may differ.
  if (!live && count !== values.length) invalid(`${path}.count`, "differs from the number of values");
  const x = int(o.x, `${path}.x`, U32);
  let wireIds: number[] | undefined;
  if (o.wireIds !== undefined) {
    if (!isBankTable(id)) invalid(`${path}.wireIds`, "only a bank table carries wire ids");
    wireIds = arr(o.wireIds, `${path}.wireIds`, SOURCE_LIMITS.wireIds).map((n, i) => int(n, `${path}.wireIds[${i}]`, U32));
  }
  return {
    kind: "enum",
    section,
    id,
    tc,
    min,
    max,
    def,
    step,
    ...(unit !== undefined ? { unit } : {}),
    count,
    values,
    x,
    ...(wireIds !== undefined ? { wireIds } : {})
  };
}

function records(list: unknown[], live: boolean, accept: (section: number) => boolean): SharedRecord[] {
  const out = new Array<SharedRecord>(list.length);
  for (let i = 0; i < list.length; i++) out[i] = record(list[i], `source.records[${i}]`, live, accept);
  return out;
}

/** A `{ '<block>': T }` dictionary: plain decimal block numbers 0..255 as keys. */
function blockKeyed<T>(v: unknown, path: string, f: (x: unknown, p: string) => T): Record<number, T> {
  const o = obj(v, path);
  const keys = Object.keys(o);
  if (keys.length > SOURCE_LIMITS.maxBlock + 1) invalid(path, `more than ${SOURCE_LIMITS.maxBlock + 1} entries`);
  const out: Record<number, T> = {};
  for (const k of keys) {
    if (!/^(0|[1-9]\d{0,2})$/.test(k) || Number(k) > SOURCE_LIMITS.maxBlock) invalid(path, `expected block numbers 0..${SOURCE_LIMITS.maxBlock} as keys`);
    out[Number(k)] = f(o[k], `${path}["${k}"]`);
  }
  return out;
}

function liveScope(v: unknown): SharedLiveScope {
  const path = "source.scope";
  const o = obj(v, path);
  const blocks = arr(o.blocks, `${path}.blocks`, SOURCE_LIMITS.maxBlock + 1).map((b, i) => int(b, `${path}.blocks[${i}]`, SOURCE_LIMITS.maxBlock));
  if (new Set(blocks).size !== blocks.length) invalid(`${path}.blocks`, "lists a block twice");
  const maxParamId = int(o.maxParamId, `${path}.maxParamId`, SOURCE_LIMITS.maxParamId);
  const bounds = blockKeyed(o.bounds, `${path}.bounds`, (x, p) => int(x, p, SOURCE_LIMITS.maxParamId));
  const idLists = o.idLists === undefined ? undefined : blockKeyed(o.idLists, `${path}.idLists`, (x, p) =>
    arr(x, p, SOURCE_LIMITS.idList).map((n, i) => int(n, `${p}[${i}]`, SOURCE_LIMITS.liveParamId)));
  return {
    blocks,
    maxParamId,
    bounds,
    ...(idLists !== undefined ? { idLists } : {}),
    extended: bool(o.extended, `${path}.extended`),
    above160: bool(o.above160, `${path}.above160`),
    hinted: bool(o.hinted, `${path}.hinted`)
  };
}

/** The walk statistics without `abortReason` (free text: dropped, never stored). */
function liveWalk(v: unknown): SharedLiveWalk {
  const path = "source.walk";
  const o = obj(v, path);
  const n = (k: string): number => int(o[k], `${path}.${k}`, U32);
  const stats = {
    queries: n("queries"),
    lostReplies: n("lostReplies"),
    recoveredReplies: n("recoveredReplies"),
    unresolvedReplies: n("unresolvedReplies"),
    placeholderSlots: n("placeholderSlots"),
    missingSlots: n("missingSlots"),
    silentAddresses: n("silentAddresses")
  };
  let pseudoReplies: SharedLiveWalk["pseudoReplies"];
  if (o.pseudoReplies !== undefined) {
    const q = obj(o.pseudoReplies, `${path}.pseudoReplies`);
    pseudoReplies = {
      endMarker: int(q.endMarker, `${path}.pseudoReplies.endMarker`, U32),
      duplicateId: int(q.duplicateId, `${path}.pseudoReplies.duplicateId`, U32),
      implausible: int(q.implausible, `${path}.pseudoReplies.implausible`, U32)
    };
  }
  const boundHits = arr(o.boundHits, `${path}.boundHits`, SOURCE_LIMITS.boundHits).map((h, i) => {
    const q = obj(h, `${path}.boundHits[${i}]`);
    return {
      block: int(q.block, `${path}.boundHits[${i}].block`, U16),
      lastReal: int(q.lastReal, `${path}.boundHits[${i}].lastReal`, U16),
      bound: int(q.bound, `${path}.boundHits[${i}].bound`, U16)
    };
  });
  const extension = o.extension === undefined ? undefined : oneOf(o.extension, `${path}.extension`, ["done", "skipped", "aborted"] as const);
  return {
    ...stats,
    ...(pseudoReplies !== undefined ? { pseudoReplies } : {}),
    boundHits,
    ...(extension !== undefined ? { extension } : {})
  };
}

function commonFields(s: Record<string, unknown>) {
  const codecVersion = typeof s.codecVersion === "string" && s.codecVersion.length <= SOURCE_LIMITS.codecVersion && CODEC_VERSION_RE.test(s.codecVersion)
    ? s.codecVersion
    : invalid("source.codecVersion", `expected a version stamp like 0.12.0-beta.1 of at most ${SOURCE_LIMITS.codecVersion} characters`);
  return {
    capturedAt: coarsenCapturedAt(s.capturedAt),
    firmware: versionOrNull(s.firmware, "source.firmware"),
    codecVersion
  };
}

function editorCacheSource(s: Record<string, unknown>, recs: unknown[]): SharedEditorCacheSource {
  if (s.space !== "section") invalid("source.space", "an editor-cache source has space section");
  const common = commonFields(s);
  const declared = new Set<number>();
  const sections = arr(s.sections, "source.sections", SOURCE_LIMITS.sections).map((x, i) => {
    const q = obj(x, `source.sections[${i}]`);
    const tag = int(q.tag, `source.sections[${i}].tag`, U16);
    if (declared.has(tag)) invalid(`source.sections[${i}].tag`, "section declared twice");
    declared.add(tag);
    return { tag, count: int(q.count, `source.sections[${i}].count`, U32) };
  });
  const om = obj(s.omitted, "source.omitted");
  const omitted = { tables: int(om.tables, "source.omitted.tables", U16), records: int(om.records, "source.omitted.records", U16) };
  let header: SharedEditorCacheSource["header"] = null;
  if (s.header !== null) {
    const h = obj(s.header, "source.header");
    header = {
      major: int(h.major, "source.header.major", U16),
      minor: int(h.minor, "source.header.minor", U16),
      sectionCount: int(h.sectionCount, "source.header.sectionCount", U32)
    };
  }
  const fileVersion = versionOrNull(s.fileVersion, "source.fileVersion");
  // contentSha256 is a fingerprint of the uploader's redacted file: never stored, whatever it holds.
  return {
    kind: "editor-cache",
    space: "section",
    ...common,
    sections,
    omitted,
    header,
    fileVersion,
    contentSha256: null,
    records: records(recs, false, (t) => declared.has(t))
  };
}

function liveSource(kind: "live-readonly" | "live-full", s: Record<string, unknown>, recs: unknown[]): SharedLiveSource {
  if (s.space !== "block") invalid("source.space", "a live source has space block");
  const common = commonFields(s);
  const scope = liveScope(s.scope);
  const walk = liveWalk(s.walk);
  const blocks = new Set(scope.blocks);
  return { kind, space: "block", ...common, scope, walk, records: records(recs, true, (b) => blocks.has(b)) };
}

// ─────────────────────────────────────────── the contribution ───────────────────────────────────────────

export interface Contribution {
  model: number;
  firmware: string;
  kind: FactKind;
  rawFormat: number;
  /** The sanitized copy: what is stored and served. */
  source: SharedSource;
  app: Record<string, string>;
  consentAt: string;
  consentVersion: number;
}

export interface ContributionOptions {
  /** Plausibility floor; default PLAUSIBILITY_FLOOR. `null` skips it (unit tests with small sources). */
  floor?: PlausibilityFloor | null;
  contributeModels?: readonly number[];
}

/**
 * Validates and sanitizes one contribution (module comment for the order and the answers). Never throws for
 * anything in `b`; never echoes a value from the source.
 */
export function parseContribution(b: unknown, nowMs: number, opts: ContributionOptions = {}): Parsed<Contribution> {
  // ── 1. envelope ──
  if (!isPlain(b)) return badRequest("request body must be a JSON object");
  const model = b.model;
  if (typeof model !== "number" || !Number.isInteger(model) || model < 0 || model > 255) return badRequest("model must be an integer 0..255");
  if (!(opts.contributeModels ?? CONTRIBUTE_MODELS).includes(model)) {
    return refuse(409, "unsupported-model", { message: "definition sources are not collected for this model" });
  }
  if (!isCanonicalFirmware(b.firmware)) return badRequest('firmware must be "<major>.<minor>" without leading zeros, like 13.0');
  const firmware = b.firmware;
  if (typeof b.kind !== "string" || !(SHARED_KINDS as readonly string[]).includes(b.kind)) {
    return badRequest(`kind must be one of ${SHARED_KINDS.join(", ")}`);
  }
  const kind = b.kind as FactKind;
  const rawFormat = b.rawFormat;
  if (typeof rawFormat !== "number" || !Number.isInteger(rawFormat) || rawFormat < 1) return badRequest("rawFormat must be a positive integer");
  if (!RAW_FORMATS.includes(rawFormat)) {
    return refuse(422, "unsupported-raw-format", { message: `raw format ${rawFormat} is not supported (supported: ${RAW_FORMATS.join(", ")})` });
  }
  if (b.consentAt === undefined || b.consentAt === null || b.consentVersion === undefined || b.consentVersion === null) {
    return badRequest("consentAt and consentVersion are required", "consent-required");
  }
  const consentMs = typeof b.consentAt === "string" && /^\d{4}-\d{2}-\d{2}T/.test(b.consentAt) ? Date.parse(b.consentAt) : NaN;
  if (!Number.isFinite(consentMs)) return badRequest("consentAt must be an ISO 8601 timestamp", "consent-required");
  if (Math.abs(consentMs - nowMs) > CONSENT_SKEW_SECONDS * 1000) {
    return badRequest("consentAt must be within 24 hours of the server time", "consent-required");
  }
  const consentVersion = b.consentVersion;
  if (typeof consentVersion !== "number" || !Number.isInteger(consentVersion) || consentVersion < 1 || consentVersion > 32767) {
    return badRequest("consentVersion must be an integer 1..32767", "consent-required");
  }
  if (consentVersion < MIN_SHARE_CONSENT_VERSION) {
    return badRequest(`consent to text ${consentVersion} is no longer accepted (minimum ${MIN_SHARE_CONSENT_VERSION})`, "consent-required");
  }
  if (!isPlain(b.source)) return badRequest("source must be an object (one raw definition source)");
  const s = b.source;

  // ── 2. unsafe values ──
  const unsafe = findUnsafeValue(s, "source");
  if (unsafe) return refuse(422, "invalid-source", unsafe);

  try {
    if (s.kind !== kind) invalid("source.kind", "differs from the envelope kind");
    const recs = arr(s.records, "source.records", SOURCE_LIMITS.records);

    // ── 3. privacy (before the shape, as the codec's sanitizer: these are refusals, not malformations) ──
    if (kind === "editor-cache" && s.issues !== undefined) {
      return refuse(422, "tolerant-source", { message: "a tolerant parse (with skipped stretches) is not shared" });
    }
    for (const r of recs) {
      if (isPlain(r) && typeof r.id === "number" && isUserNameTable(r.id)) {
        return refuse(422, "contains-user-data", { message: "the source contains a user name table (preset or user cab names)" });
      }
    }

    // ── 4. shape ──
    const source: SharedSource = kind === "editor-cache" ? editorCacheSource(s, recs) : liveSource(kind, s, recs);
    const dup = conflictingDuplicate(kind, source.records);
    if (dup >= 0) invalid(`source.records[${dup}]`, "repeats a (section, id) of an earlier record with different content");

    // ── 5. consistency ──
    if (source.firmware !== firmware) {
      return refuse(422, "firmware-inconsistent", { message: "the source's firmware differs from the envelope's firmware" });
    }
    if (source.kind === "editor-cache") {
      if (source.header === null) invalid("source.header", "an editor-cache source needs the cache header");
      const header = source.header!;
      const headerVersion = `${header.major}.${header.minor}`;
      if (source.fileVersion !== null && source.fileVersion !== headerVersion) {
        return refuse(422, "version-mismatch", { message: "the file name's version differs from the cache header's version" });
      }
      if (header.sectionCount !== source.sections.length) invalid("source.header.sectionCount", "differs from the number of sections");
      const declared = source.sections.reduce((n, x) => n + x.count, 0);
      if (declared !== source.records.length + source.omitted.records) {
        invalid("source.sections", "the section counts differ from the records plus the omitted records");
      }
      const perSection = new Map<number, number>();
      for (const r of source.records) perSection.set(r.section, (perSection.get(r.section) ?? 0) + 1);
      for (let i = 0; i < source.sections.length; i++) {
        if ((perSection.get(source.sections[i].tag) ?? 0) > source.sections[i].count) {
          invalid(`source.sections[${i}].count`, "is smaller than the records in that section");
        }
      }
    }

    // ── 6. plausibility floor ──
    const floor = opts.floor === undefined ? PLAUSIBILITY_FLOOR : opts.floor;
    if (floor) {
      const positions = uniquePositions(source.records);
      const carrying = recordSections(source.records);
      if (source.kind === "editor-cache") {
        if (carrying < floor.editorCache.sections || positions < floor.editorCache.records) {
          return refuse(422, "implausible", {
            message: `an editor cache has records in at least ${floor.editorCache.sections} sections and ${floor.editorCache.records} distinct records`,
            sections: carrying,
            records: positions
          });
        }
      } else if (carrying < floor.live.blocks || positions < floor.live.records) {
        return refuse(422, "implausible", {
          message: `a device read has records in at least ${floor.live.blocks} blocks and ${floor.live.records} distinct records`,
          blocks: carrying,
          records: positions
        });
      }
    }

    return {
      ok: true,
      value: {
        model,
        firmware,
        kind,
        rawFormat,
        source,
        app: sanitizeApp(b.app),
        consentAt: new Date(consentMs).toISOString(),
        consentVersion
      }
    };
  } catch (e) {
    if (e instanceof Refused) return e.refusal;
    throw e; // a bug in the validator, not a problem of the input
  }
}

// ─────────────────────────────────────────── the small requests ───────────────────────────────────────────

/** The public listing query `?model=<0..255>&firmware=<x.y>[&rawFormat=<1..100>]` (rawFormat defaults to 1). */
export function parseListQuery(q: URLSearchParams): Parsed<{ model: number; firmware: string; rawFormat: number }> {
  const m = q.get("model") ?? "";
  const model = /^\d{1,3}$/.test(m) ? Number(m) : NaN;
  if (!Number.isInteger(model) || model > 255) return badRequest("model must be an integer 0..255");
  const firmware = normalizeFirmware(q.get("firmware") ?? "");
  if (!firmware) return badRequest("firmware must look like 13.0");
  const rf = q.get("rawFormat");
  let rawFormat = RAW_FORMAT_MAX;
  if (rf !== null) {
    rawFormat = /^\d{1,3}$/.test(rf) ? Number(rf) : NaN;
    if (!Number.isInteger(rawFormat) || rawFormat < 1 || rawFormat > 100) return badRequest("rawFormat must be an integer 1..100");
  }
  return { ok: true, value: { model, firmware, rawFormat } };
}

export type WithdrawRequest =
  | { sourceId: string }
  | { all: true; model: number | null; firmware: string | null };

/** `{ sourceId }` or `{ all: true, model?, firmware? }`. */
export function parseWithdrawRequest(b: unknown): Parsed<WithdrawRequest> {
  if (!isPlain(b)) return badRequest("request body must be a JSON object");
  const hasId = b.sourceId !== undefined;
  const hasAll = b.all !== undefined;
  if (hasId === hasAll) return badRequest("send either { sourceId } or { all: true }");
  if (hasId) {
    if (b.model !== undefined || b.firmware !== undefined) return badRequest("model and firmware go with { all: true } only");
    const sourceId = parseRowId(b.sourceId);
    return sourceId ? { ok: true, value: { sourceId } } : badRequest("sourceId must be a source id");
  }
  if (b.all !== true) return badRequest("all must be true");
  let model: number | null = null;
  if (b.model !== undefined && b.model !== null) {
    if (typeof b.model !== "number" || !Number.isInteger(b.model) || b.model < 0 || b.model > 255) return badRequest("model must be an integer 0..255");
    model = b.model;
  }
  let firmware: string | null = null;
  if (b.firmware !== undefined && b.firmware !== null) {
    firmware = typeof b.firmware === "string" ? normalizeFirmware(b.firmware) : null;
    if (!firmware) return badRequest("firmware must look like 13.0");
  }
  return { ok: true, value: { all: true, model, firmware } };
}

export interface ReportRequest {
  sourceId: string;
  verdict: "passed" | "failed";
  checked: number;
  answered: number;
  mismatches: number;
  app: Record<string, string>;
}

/** Most targets one spot check reports (the schema's bound). */
export const MAX_SPOT_CHECK_TARGETS = 64;
/** Fewest targets a spot check runs with (the codec refuses fewer): a `passed` report below it is not a check. */
export const MIN_SPOT_CHECK_TARGETS = 12;
/** A `passed` check had answers for at least this share of its targets (the codec's verdict rule: ≥ 90 %). */
export const MIN_PASSED_ANSWER_RATIO = 0.9;

/**
 * `{ sourceId, verdict, checked, answered, mismatches, app? }`: counts 0..64 with mismatches ≤ answered ≤ checked,
 * and `failed` exactly when a mismatch was found (the spot check's verdict rule; `inconclusive` is never reported).
 * Plausible outcomes only: `passed` needs ≥ 12 targets checked and ≥ 90 % of them answered, `failed` an answer.
 */
export function parseReportRequest(b: unknown): Parsed<ReportRequest> {
  if (!isPlain(b)) return badRequest("request body must be a JSON object");
  const sourceId = parseRowId(b.sourceId);
  if (!sourceId) return badRequest("sourceId must be a source id");
  if (b.verdict !== "passed" && b.verdict !== "failed") return badRequest("verdict must be passed or failed");
  const count = (v: unknown) => (typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= MAX_SPOT_CHECK_TARGETS ? v : null);
  const checked = count(b.checked);
  const answered = count(b.answered);
  const mismatches = count(b.mismatches);
  if (checked === null || answered === null || mismatches === null) {
    return badRequest(`checked, answered and mismatches must be integers 0..${MAX_SPOT_CHECK_TARGETS}`);
  }
  if (answered > checked || mismatches > answered) return badRequest("expected mismatches <= answered <= checked");
  if ((b.verdict === "failed") !== (mismatches > 0)) return badRequest("a failed verdict has mismatches, a passed one has none");
  if (b.verdict === "passed" && (checked < MIN_SPOT_CHECK_TARGETS || answered * 10 < checked * MIN_PASSED_ANSWER_RATIO * 10)) {
    return badRequest(`a passed check has at least ${MIN_SPOT_CHECK_TARGETS} targets checked and 90 % of them answered`);
  }
  if (b.verdict === "failed" && answered < 1) return badRequest("a failed check has at least one answer");
  return { ok: true, value: { sourceId, verdict: b.verdict, checked, answered, mismatches, app: sanitizeApp(b.app) } };
}
