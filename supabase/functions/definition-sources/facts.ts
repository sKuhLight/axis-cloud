// Server-computed facts of a shared definition source: the canonical JSON text, the content FACT HASH, the summary,
// the quality and the coverage score. None of them is ever taken from the client. Pure (web-standard APIs only), so
// facts.test.ts runs without a Supabase stack.
//
// PARITY: canonicalJson() and sourceFactCanonical()/sourceFactHash() reproduce the public forgefx-midi codec
// (src/cache/share.ts, FACT_HASH_VERSION 1) byte for byte. Clients use the codec's hash to tell "already shared /
// identical" without a download; the backend dedupes and confirms by this one. The two are pinned by the synthetic
// golden vectors in fixtures/ (copied verbatim from the codec repository: change them only together with a
// FACT_HASH_VERSION bump on both sides). A mismatch would only cost dedupe / local "identical" detection, never
// security: every client re-validates, re-derives and spot-checks what it downloads.
//
// ## canonicalJson (the text that is hashed)
// No whitespace; object keys (own, enumerable, an `undefined` value skipped) in ascending UTF-16 code-unit order
// (`"10"` before `"9"`); arrays in order (an `undefined` element is an error); strings as JSON.stringify writes them;
// an INTEGER as its decimal digits (`-0` is `0`), any other finite number as `String(Number(x.toPrecision(6)))`
// (six significant digits: absorbs f32 noise, `0.10000000149011612` is `0.1`); anything else (NaN, infinities,
// bigint, functions, class instances such as Date, nesting deeper than 64) throws. Lossy by design: for hashing only.
//
// ## The fact document
//   { v: 1, model, firmware, kind, rawFormat, records, …kind part }
//   - model 0..255 and canonical firmware are the key the source is filed under (the envelope), not read from it;
//   - records: each record reduced to its known fields (as the codec copies them), identical repeats of a
//     (section, id) collapsed to the first, a repeat with DIFFERENT content refused, sorted by (section, id);
//   - editor-cache: the full records (kind section id tc min max def step [unit] t1 t2 [taper] [placeholder] /
//     kind section id tc min max def step [unit] count values x [wireIds]) plus `sections` (sorted by tag, count),
//     `header` and `omitted`;
//   - live: the kind-free projection { section, id, tc, min, max, def, step, values (only when non-empty),
//     placeholder (only `true` on a float) } plus `scope` { blocks (sorted), extended, above160, hinted }. Unit,
//     taper, kind, count, x, t1, t2, maxParamId, bounds and idLists follow the device's current state or the
//     host's settings, so two honest reads of one firmware must not differ in them.
// Left out: id, origin, capturedAt, codecVersion, fileVersion, contentSha256, issues and the live walk statistics.

import type { SharedEditorCacheSource, SharedLiveSource, SharedSource } from "./validate.ts";

/** Version of the fact document (`v`). Bump together with the codec, never alone. */
export const FACT_HASH_VERSION = 1;
/** The raw envelope format the fact document names when the caller gives none (the codec's RAW_FORMAT). */
export const DEFAULT_RAW_FORMAT = 1;

// ─────────────────────────────────────────── canonical JSON ───────────────────────────────────────────

const MAX_DEPTH = 64;

function isPlainObject(v: object): boolean {
  const p = Object.getPrototypeOf(v);
  return p === Object.prototype || p === null;
}

/** The codec's canonical number text (fingerprint.ts `canonicalNumber`): six significant digits, `-0` as `0`. */
export function canonicalNumber(x: number): string {
  if (!Number.isFinite(x)) return "NaN";
  const n = Number(x.toPrecision(6));
  return n === 0 ? "0" : String(n);
}

function numberText(x: number): string {
  if (!Number.isFinite(x)) throw new TypeError("canonicalJson: non-finite number");
  return Number.isInteger(x) ? String(x) : canonicalNumber(x);
}

function writeCanonical(v: unknown, out: string[], depth: number): void {
  if (v === null) {
    out.push("null");
    return;
  }
  switch (typeof v) {
    case "boolean":
      out.push(v ? "true" : "false");
      return;
    case "number":
      out.push(numberText(v));
      return;
    case "string":
      out.push(JSON.stringify(v));
      return;
    case "object":
      break;
    default:
      throw new TypeError(`canonicalJson: unsupported value (${typeof v})`);
  }
  if (depth >= MAX_DEPTH) throw new RangeError(`canonicalJson: nested deeper than ${MAX_DEPTH} levels`);
  if (Array.isArray(v)) {
    out.push("[");
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out.push(",");
      writeCanonical(v[i], out, depth + 1);
    }
    out.push("]");
    return;
  }
  if (!isPlainObject(v as object)) throw new TypeError("canonicalJson: only plain objects and arrays are supported");
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).filter((k) => o[k] !== undefined).sort();
  out.push("{");
  keys.forEach((k, i) => {
    if (i > 0) out.push(",");
    out.push(JSON.stringify(k), ":");
    writeCanonical(o[k], out, depth + 1);
  });
  out.push("}");
}

/** The canonical JSON text of a value (rules above). Throws TypeError / RangeError, never echoing a value. */
export function canonicalJson(value: unknown): string {
  const out: string[] = [];
  writeCanonical(value, out, 0);
  return out.join("");
}

// ─────────────────────────────────────────── the codec's record copy ───────────────────────────────────────────
// The fact document is built from copies of the known fields only, with the codec's own minimal checks, so a
// source hashes the same here whether or not it went through validate.ts (the golden vectors include shapes the
// validator refuses, e.g. a missing header).

const U16 = 0xffff;
const U32 = 0xffffffff;
const FLOAT_LIMIT = 3.5e38;
/** Canonical `<major>.<minor>`: decimal parts, no leading zeros. */
export const CANONICAL_VERSION_RE = /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/;
/** The live walker's unit token. */
export const UNIT_RE = /^[A-Za-z%°µΩ/]{1,8}$/;
export const TAPER_SHAPES = ["linear", "log", "flat", "custom", "unknown"] as const;

const bad = (what: string): never => {
  throw new TypeError(`facts: ${what}`);
};
const obj = (v: unknown, what: string): Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : bad(`${what} is not an object`);
const list = (v: unknown, what: string): readonly unknown[] => (Array.isArray(v) ? v : bad(`${what} is not an array`));
const int = (v: unknown, what: string, max: number): number =>
  typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= max ? (v === 0 ? 0 : v) : bad(`${what} is not an integer 0..${max}`);
const flt = (v: unknown, what: string): number =>
  typeof v === "number" && Number.isFinite(v) && Math.abs(v) <= FLOAT_LIMIT ? (v === 0 ? 0 : v) : bad(`${what} is not a finite number`);
const text = (v: unknown, what: string): string => (typeof v === "string" ? v : bad(`${what} is not a string`));
const oneOf = <T extends string>(v: unknown, what: string, set: readonly T[]): T =>
  typeof v === "string" && (set as readonly string[]).includes(v) ? (v as T) : bad(`${what} is not one of ${set.join(" | ")}`);
const version = (v: unknown, what: string): string =>
  typeof v === "string" && CANONICAL_VERSION_RE.test(v) ? v : bad(`${what} is not a canonical major.minor version`);
const ints = (v: unknown, what: string, max: number): number[] => list(v, what).map((n, i) => int(n, `${what}[${i}]`, max));

function copyTaper(v: unknown, what: string): Record<string, unknown> {
  const o = obj(v, what);
  return {
    shape: oneOf(o.shape, `${what}.shape`, TAPER_SHAPES),
    err: o.err === null ? null : flt(o.err, `${what}.err`),
    reliable: typeof o.reliable === "boolean" ? o.reliable : bad(`${what}.reliable is not a boolean`),
    points: list(o.points, `${what}.points`).map((p, i) => {
      const pair = list(p, `${what}.points[${i}]`);
      if (pair.length !== 2) bad(`${what}.points[${i}] is not a pair`);
      return [flt(pair[0], `${what}.points[${i}][0]`), flt(pair[1], `${what}.points[${i}][1]`)];
    })
  };
}

type FactRecord = Record<string, unknown> & { kind: "float" | "enum"; section: number; id: number };

function copyRecord(v: unknown, i: number): FactRecord {
  const at = `records[${i}]`;
  const r = obj(v, at);
  const section = int(r.section, `${at}.section`, U16);
  const id = int(r.id, `${at}.id`, U16);
  const tc = int(r.tc, `${at}.tc`, U32);
  const min = flt(r.min, `${at}.min`);
  const max = flt(r.max, `${at}.max`);
  const def = flt(r.def, `${at}.def`);
  const step = flt(r.step, `${at}.step`);
  const unit = r.unit === undefined ? undefined : text(r.unit, `${at}.unit`);
  if (unit !== undefined && !UNIT_RE.test(unit)) bad(`${at}.unit is not a unit token`);
  if (r.kind === "float") {
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
      t1: int(r.t1, `${at}.t1`, U32),
      t2: int(r.t2, `${at}.t2`, U32),
      ...(r.taper !== undefined ? { taper: copyTaper(r.taper, `${at}.taper`) } : {}),
      ...(r.placeholder === true ? { placeholder: true } : {})
    };
  }
  if (r.kind === "enum") {
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
      count: int(r.count, `${at}.count`, U32),
      values: list(r.values, `${at}.values`).map((s, k) => text(s, `${at}.values[${k}]`)),
      x: int(r.x, `${at}.x`, U32),
      ...(r.wireIds !== undefined ? { wireIds: ints(r.wireIds, `${at}.wireIds`, U32) } : {})
    };
  }
  return bad(`${at}.kind is neither float nor enum`);
}

/** The kind-free projection of a live record. */
function liveProjection(r: FactRecord): Record<string, unknown> & { section: number; id: number } {
  const values = r.kind === "enum" ? (r.values as string[]) : [];
  return {
    section: r.section,
    id: r.id,
    tc: r.tc,
    min: r.min,
    max: r.max,
    def: r.def,
    step: r.step,
    ...(values.length > 0 ? { values } : {}),
    ...(r.kind === "float" && r.placeholder === true ? { placeholder: true } : {})
  };
}

export type FactKind = "editor-cache" | "live-readonly" | "live-full";

/** What the fact hash sees of the records: the full copies of an editor cache, the projections of a live source. */
function projectRecords(kind: FactKind, copies: readonly FactRecord[]): Array<Record<string, unknown> & { section: number; id: number }> {
  return kind === "editor-cache" ? [...copies] : copies.map(liveProjection);
}

/** Items by (section, id); null when two items of one position differ in `textOf`. Identical repeats collapse. */
function uniqueByPosition<T extends { section: number; id: number }>(items: readonly T[], textOf: (t: T) => string): T[] | null {
  const seen = new Map<string, string>();
  const out: T[] = [];
  for (const it of items) {
    const key = `${it.section}:${it.id}`;
    const t = textOf(it);
    const prior = seen.get(key);
    if (prior === undefined) {
      seen.set(key, t);
      out.push(it);
    } else if (prior !== t) {
      return null;
    }
  }
  return out;
}

/**
 * The duplicate rule on its own (validate.ts): the index of the first record that repeats an earlier record's
 * (section, id) with different content (as the fact hash sees it), or -1. Identical repeats are not a conflict.
 * Assumes records the validator already checked.
 */
export function conflictingDuplicate(kind: FactKind, records: readonly unknown[]): number {
  const copies = records.map((r, i) => copyRecord(r, i));
  const projected = projectRecords(kind, copies);
  const seen = new Map<string, string>();
  for (let i = 0; i < projected.length; i++) {
    const key = `${projected[i].section}:${projected[i].id}`;
    const t = canonicalJson(projected[i]);
    const prior = seen.get(key);
    if (prior === undefined) seen.set(key, t);
    else if (prior !== t) return i;
  }
  return -1;
}

function copyScopeForFacts(v: unknown): { blocks: number[]; extended: boolean; above160: boolean; hinted: boolean } {
  const s = obj(v, "scope");
  const flag = (k: string): boolean => (typeof s[k] === "boolean" ? (s[k] as boolean) : bad(`scope.${k} is not a boolean`));
  // The codec checks the whole scope (maxParamId, bounds, idLists) even though only this part is hashed.
  const blocks = ints(s.blocks, "scope.blocks", U16);
  int(s.maxParamId, "scope.maxParamId", U16);
  const keyed = (d: unknown, what: string, f: (x: unknown, w: string) => unknown) => {
    const o = obj(d, what);
    for (const k of Object.keys(o)) {
      if (!/^(0|[1-9]\d*)$/.test(k)) bad(`${what} has a key that is not an integer`);
      f(o[k], `${what}[${k}]`);
    }
  };
  keyed(s.bounds, "scope.bounds", (x, w) => int(x, w, U16));
  if (s.idLists !== undefined) keyed(s.idLists, "scope.idLists", (x, w) => ints(x, w, U16));
  return { blocks, extended: flag("extended"), above160: flag("above160"), hinted: flag("hinted") };
}

/** What a source is filed under. `rawFormat` defaults to the codec's RAW_FORMAT (1): the backend passes the
 *  envelope's format, so a hash is scoped to its raw format. */
export interface SourceFactKey {
  model: number;
  firmware: string;
  rawFormat?: number;
}

function factDocument(src: unknown, key: SourceFactKey): Record<string, unknown> {
  const s = obj(src, "source");
  const kind = oneOf(s.kind, "kind", ["editor-cache", "live-readonly", "live-full", "live-probe"] as const);
  if (kind === "live-probe") throw new RangeError("facts: a live-probe source has no fact hash");
  const k = obj(key, "key");
  const model = int(k.model, "model", 255);
  const firmware = version(k.firmware, "firmware");
  const rawFormat = k.rawFormat === undefined ? DEFAULT_RAW_FORMAT : int(k.rawFormat, "rawFormat", 100);
  const copies = list(s.records, "records").map((r, i) => copyRecord(r, i));
  const unique = uniqueByPosition(projectRecords(kind, copies), (r) => canonicalJson(r)) ??
    bad("records repeat a (section, id) with different content");
  unique.sort((a, b) => a.section - b.section || a.id - b.id);
  const doc: Record<string, unknown> = { v: FACT_HASH_VERSION, model, firmware, kind, rawFormat, records: unique };
  if (kind === "editor-cache") {
    const om = obj(s.omitted, "omitted");
    const h = s.header === null ? null : obj(s.header, "header");
    doc.sections = list(s.sections, "sections")
      .map((x, i) => {
        const o = obj(x, `sections[${i}]`);
        return { tag: int(o.tag, `sections[${i}].tag`, U16), count: int(o.count, `sections[${i}].count`, U32) };
      })
      .sort((a, b) => a.tag - b.tag || a.count - b.count);
    doc.header = h === null
      ? null
      : { major: int(h.major, "header.major", U16), minor: int(h.minor, "header.minor", U16), sectionCount: int(h.sectionCount, "header.sectionCount", U32) };
    doc.omitted = { tables: int(om.tables, "omitted.tables", U32), records: int(om.records, "omitted.records", U32) };
    return doc;
  }
  const scope = copyScopeForFacts(s.scope);
  if (new Set(scope.blocks).size !== scope.blocks.length) bad("scope.blocks lists a block twice");
  doc.scope = { blocks: [...scope.blocks].sort((a, b) => a - b), extended: scope.extended, above160: scope.above160, hinted: scope.hinted };
  return doc;
}

/** The exact text the fact hash is taken over (the canonical JSON of the fact document). */
export function sourceFactCanonical(src: unknown, key: SourceFactKey): string {
  return canonicalJson(factDocument(src, key));
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  let hex = "";
  for (const b of digest) hex += b.toString(16).padStart(2, "0");
  return hex;
}

/** sha256 (lower-case hex) of the UTF-8 canonical fact document. Same result as the codec's sourceFactHash. */
export async function sourceFactHash(src: unknown, key: SourceFactKey): Promise<string> {
  return await sha256Hex(sourceFactCanonical(src, key));
}

// ─────────────────────────────────────────── summary, quality, coverage ───────────────────────────────────────────
// Computed over the SANITIZED source (validate.ts types), catalog-free (no derivation server-side).

export interface SourceFacts {
  factHash: string;
  /** Counts for the listing (≤ 2 KB; no record content). */
  summary: Record<string, unknown>;
  /** 0..3, see quality(). */
  quality: number;
  /** Tie-breaker inside a kind: editor-cache = distinct positions; live = record-carrying blocks × 1000 + positions. */
  coverageScore: number;
  /** UTF-8 length of the stored (sanitized) source as compact JSON — what the quotas charge and a download costs. */
  bytes: number;
}

const headerVersionOf = (s: SharedEditorCacheSource): string | null => (s.header ? `${s.header.major}.${s.header.minor}` : null);

/**
 * Quality (catalog-free):
 *   editor-cache — 3 when the file is self-consistent (header present, its section count = the sections, the
 *     section counts add up to records + omitted, every record in a declared section, the file name's version null
 *     or the header's) AND the header version is the device firmware; 2 when only the version differs (a file of
 *     another firmware matched to this device). validate.ts refuses every other inconsistency, so an accepted
 *     editor-cache source is 2 or 3 (a lower value only for a source that skipped validation).
 *   live — 3 = no unresolved reply, no missing slot, no bound hit, extension not aborted; 2 = no unresolved reply
 *     but one of the others; 1 = unresolved replies.
 */
export function quality(src: SharedSource, firmware: string): number {
  if (src.kind === "editor-cache") {
    const hv = headerVersionOf(src);
    if (!src.header || src.header.sectionCount !== src.sections.length) return 1;
    const declared = src.sections.reduce((n, s) => n + s.count, 0);
    if (declared !== src.records.length + src.omitted.records) return 1;
    const tags = new Set(src.sections.map((s) => s.tag));
    if (src.records.some((r) => !tags.has(r.section))) return 1;
    if (src.fileVersion !== null && src.fileVersion !== hv) return 1;
    return hv === firmware ? 3 : 2;
  }
  const w = src.walk;
  if (w.unresolvedReplies > 0) return 1;
  if (w.missingSlots > 0 || w.boundHits.length > 0 || w.extension === "aborted") return 2;
  return 3;
}

// Everything below counts what a source SAYS, not how often it says it: identical repeats of a (section, id) are
// one position (the fact hash collapses them the same way), and a live read covers the blocks that actually carry
// records — never its self-declared scope.blocks. Otherwise padding (a record repeated N times, empty blocks
// listed in the scope) would buy plausibility, coverage score and ranking for free.

/** The first record of every (section, id) position, in source order (what the fact hash keeps). */
export function firstPerPosition<T extends { section: number; id: number }>(records: readonly T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const r of records) {
    const key = `${r.section}:${r.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(r);
  }
  return out;
}

/** Distinct (section, id) positions. */
export function uniquePositions(records: readonly { section: number; id: number }[]): number {
  return new Set(records.map((r) => `${r.section}:${r.id}`)).size;
}

/** Distinct sections (editor cache) / blocks (live read) that carry at least one record. */
export function recordSections(records: readonly { section: number }[]): number {
  return new Set(records.map((r) => r.section)).size;
}

export function coverageScore(src: SharedSource): number {
  const positions = uniquePositions(src.records);
  return src.kind === "editor-cache" ? positions : recordSections(src.records) * 1000 + positions;
}

function editorCacheSummary(src: SharedEditorCacheSource, firmware: string): Record<string, unknown> {
  const hv = headerVersionOf(src);
  const unique = firstPerPosition(src.records);
  return {
    // distinct positions (identical repeats once)
    records: unique.length,
    sections: src.sections.length,
    omittedRecords: src.omitted.records,
    headerVersion: hv,
    headerSectionCount: src.header ? src.header.sectionCount : null,
    fileVersion: src.fileVersion,
    headerMatchesFirmware: hv === firmware,
    // Label entries over all enum records (model/type lists, cab names): a size, never the labels.
    labels: unique.reduce((n, r) => n + (r.kind === "enum" ? r.values.length : 0), 0)
  };
}

function liveSummary(src: SharedLiveSource): Record<string, unknown> {
  const w = src.walk;
  const unique = firstPerPosition(src.records);
  return {
    // distinct positions, and the blocks that carry records (`scopeBlocks`: what the walk says it covered)
    records: unique.length,
    blocks: recordSections(unique),
    scopeBlocks: src.scope.blocks.length,
    maxParamId: src.scope.maxParamId,
    extended: src.scope.extended,
    above160: src.scope.above160,
    hinted: src.scope.hinted,
    units: unique.filter((r) => r.unit !== undefined).length,
    tapers: unique.filter((r) => r.kind === "float" && r.taper !== undefined).length,
    walk: {
      queries: w.queries,
      lostReplies: w.lostReplies,
      recoveredReplies: w.recoveredReplies,
      unresolvedReplies: w.unresolvedReplies,
      missingSlots: w.missingSlots,
      boundHits: w.boundHits.length,
      extension: w.extension ?? null
    }
  };
}

export function summarize(src: SharedSource, firmware: string): Record<string, unknown> {
  return src.kind === "editor-cache" ? editorCacheSummary(src, firmware) : liveSummary(src);
}

/** Every server-computed field of a sanitized source filed under (model, firmware, rawFormat). */
export async function computeFacts(src: SharedSource, key: { model: number; firmware: string; rawFormat: number }): Promise<SourceFacts> {
  return {
    factHash: await sourceFactHash(src, key),
    summary: summarize(src, key.firmware),
    quality: quality(src, key.firmware),
    coverageScore: coverageScore(src),
    bytes: new TextEncoder().encode(JSON.stringify(src)).length
  };
}
