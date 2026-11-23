// Unit tests for definition-sources/facts.ts: canonical JSON and fact-hash PARITY with the public forgefx-midi codec
// (golden vectors in fixtures/, copied verbatim from the codec repository), the hash's invariances, and the
// server-computed summary / quality / coverage score. Run with:
//   deno test supabase/functions/definition-sources/
// Synthetic data only.
import { assert, assertEquals, assertNotEquals, assertThrows } from "jsr:@std/assert@1";
import {
  canonicalJson,
  computeFacts,
  conflictingDuplicate,
  coverageScore,
  FACT_HASH_VERSION,
  quality,
  sha256Hex,
  sourceFactCanonical,
  sourceFactHash,
  summarize
} from "./facts.ts";
import { bigEditorCache, CONSENT_NOW, editorCacheFixture, envelope, GOLDENS, type Json, liveFixture } from "./synthetic-sources.ts";
import { parseContribution, type SharedEditorCacheSource, type SharedLiveSource } from "./validate.ts";

const FILES: Record<string, () => Json> = {
  "editor-cache.source.json": editorCacheFixture,
  "live-readonly.source.json": liveFixture
};

// ── golden vectors ──

Deno.test("the golden file is the codec's format 1 / fact hash version 1", () => {
  assertEquals(GOLDENS.format, 1);
  assertEquals(GOLDENS.factHashVersion, FACT_HASH_VERSION);
  assertEquals(FACT_HASH_VERSION, 1);
});

Deno.test("canonicalJson reproduces every codec vector", () => {
  assert(GOLDENS.canonicalJson.length >= 7);
  for (const v of GOLDENS.canonicalJson) assertEquals(canonicalJson(v.input), v.expected, v.name);
});

Deno.test("fact hash parity: both fixture files hash to the codec's golden values", async () => {
  assertEquals(GOLDENS.sources.length, 2);
  for (const c of GOLDENS.sources) {
    const src = FILES[c.file]();
    const key = { model: c.model, firmware: c.firmware };
    assertEquals(await sourceFactHash(src, key), c.factHash, c.name);
    // The digest is plain sha256 of the canonical text (no hidden salt or framing).
    assertEquals(await sha256Hex(sourceFactCanonical(src, key)), c.factHash, c.name);
  }
});

Deno.test("fact hash parity: every tiny vector's canonical text and hash", async () => {
  assertEquals(GOLDENS.tiny.length, 4);
  for (const c of GOLDENS.tiny) {
    const key = { model: c.model, firmware: c.firmware };
    assertEquals(sourceFactCanonical(c.source, key), c.canonical, c.name);
    assertEquals(await sourceFactHash(c.source, key), c.factHash, c.name);
  }
});

Deno.test("fact hash parity holds through the server pipeline (validate + sanitize, then hash)", async () => {
  for (const c of GOLDENS.sources) {
    const parsed = parseContribution(envelope(FILES[c.file](), { model: c.model, firmware: c.firmware }), CONSENT_NOW, { floor: null });
    assert(parsed.ok, JSON.stringify(parsed));
    const facts = await computeFacts(parsed.value.source, { model: c.model, firmware: c.firmware, rawFormat: 1 });
    assertEquals(facts.factHash, c.factHash, c.name);
  }
});

Deno.test("all golden hashes are distinct", () => {
  const all = [...GOLDENS.sources, ...GOLDENS.tiny].map((c: Json) => c.factHash);
  assertEquals(new Set(all).size, all.length);
});

// ── canonicalJson rules beyond the vectors ──

Deno.test("canonicalJson: -0, skipped undefined, null prototype, scalars, refusals", () => {
  assertEquals(canonicalJson(-0), "0");
  assertEquals(canonicalJson([-0, 0]), "[0,0]");
  assertEquals(canonicalJson({ a: undefined, b: 1 }), '{"b":1}');
  assertEquals(canonicalJson(Object.create(null, { x: { value: 1, enumerable: true } })), '{"x":1}');
  assertEquals(canonicalJson("plain"), '"plain"');
  assertEquals(canonicalJson(null), "null");
  assertEquals(canonicalJson({ b: 1, a: 2, 2: 3, 1: 4 }), canonicalJson({ 1: 4, 2: 3, a: 2, b: 1 }));
  assertThrows(() => canonicalJson({ a: Number.NaN }), TypeError);
  assertThrows(() => canonicalJson([Number.POSITIVE_INFINITY]), TypeError);
  assertThrows(() => canonicalJson(undefined), TypeError);
  assertThrows(() => canonicalJson([1, undefined]), TypeError);
  assertThrows(() => canonicalJson({ d: new Date(0) }), TypeError);
  assertThrows(() => canonicalJson(10n), TypeError);
  let deep: unknown = 1;
  for (let i = 0; i < 70; i++) deep = [deep];
  assertThrows(() => canonicalJson(deep), RangeError);
});

// ── invariances ──

const KEY = { model: 17, firmware: "12.0" };

Deno.test("the hash ignores id, origin, capturedAt, codecVersion, fileVersion, contentSha256, issues, key and record order", async () => {
  const base = await sourceFactHash(editorCacheFixture(), KEY);
  const s = editorCacheFixture();
  Object.assign(s, {
    id: "editor-cache@x#1",
    origin: "local",
    capturedAt: "2026-01-02T03:04:05.000Z",
    codecVersion: "9.9.9",
    fileVersion: null,
    contentSha256: "a".repeat(64),
    issues: []
  });
  s.records.reverse();
  s.sections.reverse();
  const shuffled = Object.fromEntries(Object.entries(s).reverse());
  assertEquals(await sourceFactHash(shuffled, KEY), base);
});

Deno.test("the hash changes with any record content, the key or the raw format", async () => {
  const base = await sourceFactHash(editorCacheFixture(), KEY);
  const s = editorCacheFixture();
  s.records[0].max = s.records[0].max + 1;
  assertNotEquals(await sourceFactHash(s, KEY), base);
  assertNotEquals(await sourceFactHash(editorCacheFixture(), { model: 18, firmware: "12.0" }), base);
  assertNotEquals(await sourceFactHash(editorCacheFixture(), { model: 17, firmware: "12.1" }), base);
  assertNotEquals(await sourceFactHash(editorCacheFixture(), { ...KEY, rawFormat: 2 }), base);
});

Deno.test("live: walk statistics, unit, taper, kind, count, maxParamId, bounds and idLists do not change the hash", async () => {
  const base = await sourceFactHash(liveFixture(), KEY);
  const s = liveFixture();
  s.walk = { ...s.walk, lostReplies: 99, unresolvedReplies: 3, extension: "aborted", abortReason: "x" };
  s.scope.maxParamId = 300;
  s.scope.bounds = {};
  delete s.scope.idLists;
  s.scope.blocks.reverse();
  for (const r of s.records) {
    if (r.kind === "float") {
      r.unit = "ms";
      r.taper = { shape: "log", err: null, reliable: false, points: [[0, 1], [1, 2]] };
      r.t1 = 0;
    } else {
      r.count = 999;
      r.x = 7;
    }
  }
  assertEquals(await sourceFactHash(s, KEY), base);
});

Deno.test("live: label lists and the scope flags are facts", async () => {
  const base = await sourceFactHash(liveFixture(), KEY);
  const s = liveFixture();
  const e = s.records.find((r: Json) => r.kind === "enum" && r.values.length > 1);
  e.values = [...e.values].reverse();
  assertNotEquals(await sourceFactHash(s, KEY), base);
  const t = liveFixture();
  t.scope.hinted = !t.scope.hinted;
  assertNotEquals(await sourceFactHash(t, KEY), base);
});

Deno.test("duplicates: identical repeats collapse, differing repeats are refused", async () => {
  const base = await sourceFactHash(editorCacheFixture(), KEY);
  const s = editorCacheFixture();
  s.records.push(structuredClone(s.records[3]));
  assertEquals(await sourceFactHash(s, KEY), base);
  assertEquals(conflictingDuplicate("editor-cache", s.records), -1);
  const d = editorCacheFixture();
  d.records.push({ ...structuredClone(d.records[3]), max: 12345 });
  assertThrows(() => sourceFactCanonical(d, KEY), TypeError);
  assertEquals(conflictingDuplicate("editor-cache", d.records), d.records.length - 1);
  // live: a repeat that differs only in unit is the same fact (the projection), so not a conflict
  const l = liveFixture();
  l.records.push({ ...structuredClone(l.records[0]), unit: "ms" });
  assertEquals(conflictingDuplicate("live-readonly", l.records), -1);
});

Deno.test("a live-probe source has no fact hash; a bad key throws", () => {
  const p = liveFixture();
  p.kind = "live-probe";
  assertThrows(() => sourceFactCanonical(p, KEY), RangeError);
  assertThrows(() => sourceFactCanonical(liveFixture(), { model: 17, firmware: "12.00" }), TypeError);
  assertThrows(() => sourceFactCanonical(liveFixture(), { model: 256, firmware: "12.0" }), TypeError);
});

// ── summary, quality, coverage ──

function sanitized(src: Json, firmware = "12.0") {
  const p = parseContribution(envelope(src, { firmware }), CONSENT_NOW, { floor: null });
  if (!p.ok) throw new Error(JSON.stringify(p));
  return p.value.source;
}

Deno.test("editor cache: quality 3 when the header names the device firmware, 2 when it names another", () => {
  const s = sanitized(editorCacheFixture()) as SharedEditorCacheSource;
  assertEquals(quality(s, "12.0"), 3);
  // The same file matched to a device on another firmware (fileVersion null, header 12.0).
  const other = editorCacheFixture();
  other.firmware = "13.0";
  other.fileVersion = null;
  const o = sanitized(other, "13.0") as SharedEditorCacheSource;
  assertEquals(quality(o, "13.0"), 2);
  assertEquals((summarize(o, "13.0") as Json).headerMatchesFirmware, false);
});

Deno.test("editor cache: summary and coverage score", () => {
  const s = sanitized(editorCacheFixture()) as SharedEditorCacheSource;
  const sum = summarize(s, "12.0") as Json;
  assertEquals(sum.records, 225);
  assertEquals(sum.sections, 5);
  assertEquals(sum.omittedRecords, 1);
  assertEquals(sum.headerVersion, "12.0");
  assertEquals(sum.headerSectionCount, 5);
  assertEquals(sum.fileVersion, "12.0");
  assertEquals(sum.headerMatchesFirmware, true);
  assertEquals(sum.labels, s.records.reduce((n, r) => n + (r.kind === "enum" ? r.values.length : 0), 0));
  assertEquals(coverageScore(s), 225);
  assert(JSON.stringify(sum).length <= 2048);
});

Deno.test("live: quality 3 / 2 / 1 from the walk statistics", () => {
  const s = sanitized(liveFixture()) as SharedLiveSource;
  assertEquals(quality(s, "12.0"), 3);
  const q = (patch: Record<string, unknown>) => quality({ ...s, walk: { ...s.walk, ...patch } } as SharedLiveSource, "12.0");
  assertEquals(q({ missingSlots: 1 }), 2);
  assertEquals(q({ boundHits: [{ block: 66, lastReal: 98, bound: 100 }] }), 2);
  assertEquals(q({ extension: "aborted" }), 2);
  assertEquals(q({ extension: "done" }), 3);
  assertEquals(q({ unresolvedReplies: 1 }), 1);
  assertEquals(q({ unresolvedReplies: 1, missingSlots: 4 }), 1);
});

Deno.test("live: summary and coverage score (blocks × 1000 + records)", () => {
  const s = sanitized(liveFixture()) as SharedLiveSource;
  const sum = summarize(s, "12.0") as Json;
  assertEquals(sum.records, 225);
  assertEquals(sum.blocks, 4);
  assertEquals(sum.maxParamId, 127);
  assertEquals(sum.hinted, true);
  assertEquals(sum.units, s.records.filter((r) => r.unit !== undefined).length);
  assertEquals(sum.tapers, 0);
  assertEquals(sum.walk, { queries: 1384, lostReplies: 2, recoveredReplies: 2, unresolvedReplies: 0, missingSlots: 0, boundHits: 0, extension: "skipped" });
  assertEquals(coverageScore(s), 4 * 1000 + 225);
  assert(JSON.stringify(sum).length <= 2048);
});

Deno.test("computeFacts: bytes = UTF-8 length of the stored (sanitized) source", async () => {
  const s = sanitized(editorCacheFixture());
  const f = await computeFacts(s, { model: 17, firmware: "12.0", rawFormat: 1 });
  assertEquals(f.bytes, new TextEncoder().encode(JSON.stringify(s)).length);
  assertEquals(f.quality, 3);
  assertEquals(f.coverageScore, 225);
  assertEquals(f.factHash, GOLDENS.sources[0].factHash);
});

// ── padding buys nothing (review fix) ──

Deno.test("identical repeats change neither the coverage score nor the summary counts", async () => {
  const honest = sanitized(bigEditorCache());
  const padded = structuredClone(bigEditorCache());
  // repeat every record of the first section 20 times, keeping the file self-consistent
  const first = padded.sections[1];
  const seed = padded.records.filter((r: Json) => r.section === first.tag);
  for (let k = 0; k < 20; k++) padded.records.push(...structuredClone(seed));
  first.count += 20 * seed.length;
  const p = sanitized(padded);
  const key = { model: 17, firmware: "12.0", rawFormat: 1 };
  const [fh, fp] = [await computeFacts(honest, key), await computeFacts(p, key)];
  // (the hash differs: the declared section counts, raised to keep the file consistent, are facts of an editor cache)
  assertNotEquals(fp.factHash, fh.factHash);
  assertEquals(fp.coverageScore, fh.coverageScore);
  assertEquals((fp.summary as Json).records, (fh.summary as Json).records);
  assertEquals((fp.summary as Json).labels, (fh.summary as Json).labels);
  assert(p.records.length > honest.records.length);
});

Deno.test("a padded source with fewer real facts ranks below the honest one (coverage score)", async () => {
  const honest = bigEditorCache();
  const padded = bigEditorCache();
  // drop the last 100 distinct records and make up the count with copies of one record
  const dropped = padded.records.splice(padded.records.length - 100, 100);
  padded.records.push(...Array.from({ length: 100 }, () => ({ ...structuredClone(padded.records[1]) })));
  // keep the section accounting consistent: the copies sit in section of records[1]
  for (const r of dropped) padded.sections.find((x: Json) => x.tag === r.section).count -= 1;
  padded.sections.find((x: Json) => x.tag === padded.records[1].section).count += 100;
  const key = { model: 17, firmware: "12.0", rawFormat: 1 };
  const [h, p] = [await computeFacts(sanitized(honest), key), await computeFacts(sanitized(padded), key)];
  assert(p.coverageScore < h.coverageScore, `${p.coverageScore} vs ${h.coverageScore}`);
  assertEquals(p.coverageScore, h.coverageScore - 100);
});

Deno.test("live: only blocks that carry records count (summary blocks, coverage score)", () => {
  const base = sanitized(liveFixture()) as SharedLiveSource;
  const wide = liveFixture();
  for (let b = 200; b < 240; b++) wide.scope.blocks.push(b);
  const w = sanitized(wide) as SharedLiveSource;
  assertEquals(coverageScore(w), coverageScore(base));
  const sum = summarize(w, "12.0") as Json;
  assertEquals([sum.blocks, sum.scopeBlocks], [4, 44]);
});
