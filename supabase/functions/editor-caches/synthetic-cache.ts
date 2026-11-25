// TEST HELPER (imported only by validate.test.ts and handler.test.ts, never by index.ts): builds SYNTHETIC editor
// caches in the layout validate.ts checks. Never use real cache files in tests — a real file carries its owner's
// preset and cab names.

type Bytes = number[];

function u16(out: Bytes, v: number) {
  out.push(v & 0xff, (v >>> 8) & 0xff);
}
function u32(out: Bytes, v: number) {
  out.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
}
function f32(out: Bytes, v: number) {
  const b = new Uint8Array(new Float32Array([v]).buffer);
  out.push(...b);
}
function name(out: Bytes, s: string) {
  const b = new TextEncoder().encode(s);
  u32(out, b.length);
  out.push(...b);
}

function recordHead(out: Bytes, id: number, tc: number) {
  u16(out, id);
  u16(out, tc);
  u16(out, 0); // pad
  f32(out, 0); // min
  f32(out, 10); // max
  f32(out, 5); // default
  f32(out, 1); // step
}

/** A 32-byte float record (t1 = t2 = 0, so it can never be read as a name list). */
export function floatRec(id: number, tc = 1): Bytes {
  const out: Bytes = [];
  recordHead(out, id, tc);
  u32(out, 0);
  u32(out, 0);
  u16(out, 0);
  return out;
}

/** An enum record (enumTail): names, then u32 x, u16 0. */
export function enumRec(id: number, names: string[], x = 0, tc = 2): Bytes {
  const out: Bytes = [];
  recordHead(out, id, tc);
  u32(out, names.length);
  for (const n of names) name(out, n);
  u32(out, x);
  u16(out, 0);
  return out;
}

/** A cab/IR bank table record (tableTail, ids 0xfff0..0xfffe): names, u16 0, u32 idCount, ids. */
export function tableRec(id: number, names: string[], wireIds: number[], tc = 3): Bytes {
  const out: Bytes = [];
  recordHead(out, id, tc);
  u32(out, names.length);
  for (const n of names) name(out, n);
  u16(out, 0);
  u32(out, wireIds.length);
  for (const w of wireIds) u32(out, w);
  return out;
}

export function section(tag: number, records: Bytes[], declaredCount = records.length): Bytes {
  const out: Bytes = [];
  u32(out, tag);
  u32(out, declaredCount);
  for (const r of records) out.push(...r);
  return out;
}

export interface HeaderOptions {
  /** Section count written at 0x2a (default: the number of sections passed). */
  declaredSections?: number;
  /** ASCII text written at 0x0a (NUL-terminated), as some files carry a build date there. */
  buildDate?: string;
}

/** A complete cache: the 46-byte header (major, minor, u16 4, optional build date, section count) + sections. */
export function cache(major: number, minor: number, sections: Bytes[], opts: HeaderOptions = {}): Uint8Array {
  const out: Bytes = [];
  u32(out, major);
  u32(out, minor);
  u16(out, 4);
  while (out.length < 0x0a) out.push(0);
  if (opts.buildDate) out.push(...new TextEncoder().encode(opts.buildDate).slice(0, 31));
  while (out.length < 0x2a) out.push(0);
  u32(out, opts.declaredSections ?? sections.length);
  for (const s of sections) out.push(...s);
  return new Uint8Array(out);
}

/** '_' repeated over the UTF-8 byte length of `s` (what the client's redaction produces; '' stays ''). */
export function blank(s: string): string {
  return "_".repeat(new TextEncoder().encode(s).length);
}

/** Made-up user names for the synthetic tables (they only need to be non-empty and recognizable). */
export const PRESET_NAMES = ["Synthetic Preset A", "Another Patch", "", "Grüße Lead", "X"];
export const USER_CAB_NAMES = ["", "My Cab One", "Room Mic Blend"];
export const FACTORY_CAB_NAMES = ["Factory Cab 1", "Factory Cab 2", "Factory Cab 3"];

/** `count` sections (tags from `firstTag`) of `perSection` float records each — bulk that makes a synthetic cache
 *  as large as the plausibility floor demands (validate.ts PLAUSIBILITY_FLOOR). */
export function fillerSections(count: number, perSection: number, firstTag = 100): Bytes[] {
  const out: Bytes[] = [];
  for (let s = 0; s < count; s++) {
    const recs: Bytes[] = [];
    for (let r = 0; r < perSection; r++) recs.push(floatRec(r, 1 + (s % 7)));
    out.push(section(firstTag + s, recs));
  }
  return out;
}

/** Shape of typicalCache(): 3 sections / 9 records of content + 20 × 55 filler records. */
export const TYPICAL = { sections: 23, records: 1109 };

/**
 * A typical cache for firmware `major.minor` that clears the plausibility floor (≥ 32 KiB, ≥ 16 sections, ≥ 500
 * records, a preset-name table): parameter records, factory + user cab banks, the preset-name table, and filler
 * sections. `redacted` blanks the user names the way the client's redaction does. `extra` adds one parameter
 * record (another unit's file → another sha256).
 */
export function typicalCache(major = 13, minor = 0, redacted = true, opts: HeaderOptions = {}, extra = false): Uint8Array {
  const user = (names: string[]) => (redacted ? names.map(blank) : names);
  const first = [floatRec(0), enumRec(1, ["Clean", "Crunch", "Lead"], 7), floatRec(2), floatRec(3)];
  if (extra) first.push(floatRec(9));
  return cache(major, minor, [
    section(1, first),
    section(11, [
      tableRec(0xfff0, FACTORY_CAB_NAMES, [1, 2, 3]),
      tableRec(0xfff3, user(USER_CAB_NAMES), [10, 11, 12]),
      floatRec(4)
    ]),
    section(40, [enumRec(0xffff, user(PRESET_NAMES)), floatRec(5)]),
    ...fillerSections(20, 55)
  ], opts);
}
