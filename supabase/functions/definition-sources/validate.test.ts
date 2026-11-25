// Unit tests for definition-sources/validate.ts: the envelope, the unsafe-value scan, the shared-source shape, the
// privacy rules, consistency and the plausibility floor — every 4xx answer of a contribution — plus the sanitized
// copy (what is stored) and the small request parsers. Run with:
//   deno test supabase/functions/definition-sources/
// Synthetic sources only (synthetic-sources.ts).
import { assert, assertEquals, assertFalse, assertStringIncludes } from "jsr:@std/assert@1";
import {
  bigEditorCache,
  bigLive,
  CONSENT_NOW,
  editorCacheFixture,
  envelope,
  type Json,
  liveFixture
} from "./synthetic-sources.ts";
import {
  coarsenCapturedAt,
  type ContributionOptions,
  findUnsafeValue,
  isUserNameTable,
  isValidLabel,
  MIN_SHARE_CONSENT_VERSION,
  normalizeFirmware,
  parseContribution,
  parseListQuery,
  parseReportRequest,
  parseWithdrawRequest,
  PLAUSIBILITY_FLOOR,
  resolveIpSalt,
  SOURCE_LIMITS
} from "./validate.ts";

const NO_FLOOR: ContributionOptions = { floor: null };

/** `ok` or `<status> <error>` (+ ` @<path>` for invalid-source). */
function outcome(body: unknown, opts: ContributionOptions = NO_FLOOR): string {
  const r = parseContribution(body, CONSENT_NOW, opts);
  if (r.ok) return "ok";
  return r.error === "invalid-source" ? `${r.status} ${r.error} @${r.fields.path}` : `${r.status} ${r.error}`;
}

/** The fixture of `kind` with `edit` applied, wrapped in an envelope. */
function edited(make: () => Json, edit: (s: Json) => void, overrides: Record<string, unknown> = {}): Json {
  const s = make();
  edit(s);
  return envelope(s, overrides);
}
const ec = (edit: (s: Json) => void, overrides?: Record<string, unknown>) => edited(editorCacheFixture, edit, overrides);
const lv = (edit: (s: Json) => void, overrides?: Record<string, unknown>) => edited(liveFixture, edit, overrides);

// ── accepted sources and the sanitized copy ──

Deno.test("both codec fixtures pass (floor off) and the sanitized copy IS the codec's shareable shape", () => {
  for (const make of [editorCacheFixture, liveFixture]) {
    const src = make();
    const r = parseContribution(envelope(src), CONSENT_NOW, NO_FLOOR);
    assert(r.ok, JSON.stringify(r));
    // Same keys, same order, same values: the fixtures are the codec's shareableSource output.
    assertEquals(JSON.stringify(r.value.source), JSON.stringify(src));
    assertEquals(r.value.model, 17);
    assertEquals(r.value.firmware, "12.0");
    assertEquals(r.value.rawFormat, 1);
    assertEquals(r.value.consentVersion, 1);
    assertEquals(r.value.app, { forgefx: "0.11.0", codec: "0.12.0-beta", axis: "0.11.0" });
  }
});

Deno.test("grown fixtures pass the plausibility floor", () => {
  assertEquals(outcome(envelope(bigEditorCache()), {}), "ok");
  assertEquals(outcome(envelope(bigLive()), {}), "ok");
});

Deno.test("stripped: contentSha256, id, origin, walk.abortReason, unknown keys; capturedAt coarsened", () => {
  const e = editorCacheFixture();
  Object.assign(e, { id: "editor-cache@2026-11-22#1", origin: "local", contentSha256: "ab".repeat(32), capturedAt: "2026-11-22T01:30:00+05:00", extra: { x: 1 } });
  e.records[0].extra = "dropped";
  e.header.extra = 1;
  const r = parseContribution(envelope(e), CONSENT_NOW, NO_FLOOR);
  assert(r.ok, JSON.stringify(r));
  const s = r.value.source as Json;
  assertEquals(s.contentSha256, null);
  assertFalse("id" in s);
  assertFalse("origin" in s);
  assertFalse("extra" in s);
  assertFalse("extra" in s.records[0]);
  assertFalse("extra" in s.header);
  assertEquals(s.capturedAt, "2026-11-21T00:00:00.000Z");
  // a contentSha256 of any shape is stripped, never stored
  const odd = editorCacheFixture();
  odd.contentSha256 = { not: "a hash" };
  const o = parseContribution(envelope(odd), CONSENT_NOW, NO_FLOOR);
  assert(o.ok);
  assertEquals((o.value.source as Json).contentSha256, null);

  const l = liveFixture();
  l.walk.abortReason = "free text from the walk";
  l.id = "live-readonly@x#1";
  l.origin = "local";
  const lr = parseContribution(envelope(l), CONSENT_NOW, NO_FLOOR);
  assert(lr.ok, JSON.stringify(lr));
  assertFalse("abortReason" in (lr.value.source as Json).walk);
  assertFalse("id" in (lr.value.source as Json));
  assertFalse(JSON.stringify(lr.value.source).includes("free text"));
});

Deno.test("coarsenCapturedAt: UTC day, offsets applied, anything unrecognized is null", () => {
  assertEquals(coarsenCapturedAt("2026-11-22T13:45:10.123Z"), "2026-11-22T00:00:00.000Z");
  assertEquals(coarsenCapturedAt("2026-11-22"), "2026-11-22T00:00:00.000Z");
  assertEquals(coarsenCapturedAt("2026-11-22T23:30:00-02:00"), "2026-11-23T00:00:00.000Z");
  for (const v of [null, undefined, 5, "2026-11-22T13:45:10", "2026-02-30", "yesterday", "2026-11-22T25:00:00Z"]) {
    assertEquals(coarsenCapturedAt(v), null, String(v));
  }
});

Deno.test("app: version stamps only", () => {
  const r = parseContribution(envelope(editorCacheFixture(), { app: { forgefx: "0.11.0", codec: "C:\\Users\\x", host: "pc", axis: 7 } }), CONSENT_NOW, NO_FLOOR);
  assert(r.ok);
  assertEquals(r.value.app, { forgefx: "0.11.0" });
});

// ── 1. envelope ──

Deno.test("envelope: 400 invalid-request", () => {
  const src = editorCacheFixture();
  assertEquals(outcome(null), "400 invalid-request");
  assertEquals(outcome([envelope(src)]), "400 invalid-request");
  assertEquals(outcome(envelope(src, { model: "17" })), "400 invalid-request");
  assertEquals(outcome(envelope(src, { model: 17.5 })), "400 invalid-request");
  assertEquals(outcome(envelope(src, { model: 256 })), "400 invalid-request");
  for (const fw of ["13.00", "013.0", "13", "13.0 ", "v13.0", 13, null]) {
    assertEquals(outcome(envelope(src, { firmware: fw })), "400 invalid-request", String(fw));
  }
  assertEquals(outcome(envelope(src, { kind: "live-probe" })), "400 invalid-request");
  assertEquals(outcome(envelope(src, { kind: undefined })), "400 invalid-request");
  assertEquals(outcome(envelope(src, { rawFormat: "1" })), "400 invalid-request");
  assertEquals(outcome(envelope(src, { rawFormat: 0 })), "400 invalid-request");
  assertEquals(outcome(envelope(null)), "400 invalid-request");
  assertEquals(outcome(envelope([src] as Json, { kind: "editor-cache", firmware: "12.0" })), "400 invalid-request");
});

Deno.test("envelope: 409 unsupported-model for a device that does not contribute", () => {
  const src = editorCacheFixture();
  for (const m of [0x07, 0x14, 0x15, 0]) assertEquals(outcome(envelope(src, { model: m })), "409 unsupported-model", String(m));
  for (const m of [0x10, 0x11, 0x12]) assertEquals(outcome(envelope(src, { model: m })), "ok", String(m));
});

Deno.test("envelope: 422 unsupported-raw-format", () => {
  assertEquals(outcome(envelope(editorCacheFixture(), { rawFormat: 2 })), "422 unsupported-raw-format");
});

Deno.test("envelope: 400 consent-required", () => {
  const src = editorCacheFixture();
  const day = 24 * 60 * 60 * 1000;
  assertEquals(outcome(envelope(src, { consentAt: undefined })), "400 consent-required");
  assertEquals(outcome(envelope(src, { consentVersion: null })), "400 consent-required");
  assertEquals(outcome(envelope(src, { consentAt: "yesterday" })), "400 consent-required");
  assertEquals(outcome(envelope(src, { consentAt: new Date(CONSENT_NOW - day - 1000).toISOString() })), "400 consent-required");
  assertEquals(outcome(envelope(src, { consentAt: new Date(CONSENT_NOW + day + 1000).toISOString() })), "400 consent-required");
  assertEquals(outcome(envelope(src, { consentAt: new Date(CONSENT_NOW - day + 1000).toISOString() })), "ok");
  assertEquals(outcome(envelope(src, { consentVersion: 0 })), "400 consent-required");
  assertEquals(outcome(envelope(src, { consentVersion: 1.5 })), "400 consent-required");
  assertEquals(MIN_SHARE_CONSENT_VERSION, 1);
});

// ── 2. unsafe values ──

Deno.test("unsafe: prototype keys anywhere in the source (as JSON.parse creates them)", () => {
  for (const at of ['"__proto__":{"x":1}', '"constructor":1', '"prototype":[]']) {
    const text = JSON.stringify(envelope(editorCacheFixture())).replace('"kind":"float"', `${at},"kind":"float"`);
    const r = parseContribution(JSON.parse(text), CONSENT_NOW, NO_FLOOR);
    assertFalse(r.ok);
    assertEquals(r.status, 422);
    assertEquals(r.error, "invalid-source");
    assertEquals(r.fields.reason, "forbidden key");
    assertStringIncludes(String(r.fields.path), "source.records[0]");
  }
});

Deno.test("unsafe: non-finite numbers, oversize strings, deep nesting, huge arrays and objects", () => {
  // 1e999 parses to Infinity
  const inf = JSON.parse(JSON.stringify(envelope(editorCacheFixture())).replace('"max":20,', '"max":1e999,'));
  assertEquals(outcome(inf), "422 invalid-source @source.records[0].max");
  assertEquals(outcome(ec((s) => (s.records[5].values[0] = "x".repeat(SOURCE_LIMITS.string + 1)))), "422 invalid-source @source.records[5].values[0]");
  let deep: Json = 1;
  for (let i = 0; i < SOURCE_LIMITS.depth + 2; i++) deep = [deep];
  assertEquals(outcome(ec((s) => (s.extra = deep))).startsWith("422 invalid-source @source.extra"), true);
  assertEquals(outcome(ec((s) => (s.extra = new Array(SOURCE_LIMITS.array + 1).fill(0)))), "422 invalid-source @source.extra");
  const many: Json = {};
  for (let i = 0; i < SOURCE_LIMITS.keys + 1; i++) many[`k${i}`] = 0;
  assertEquals(outcome(ec((s) => (s.extra = many))), "422 invalid-source @source.extra");
});

Deno.test("findUnsafeValue paths never echo free-text keys", () => {
  const r = findUnsafeValue({ ["secret name with spaces"]: { __proto__x: 1, constructor: 2 } });
  // JSON.parse would give an own "__proto__"; an object literal's `constructor` key is an own key as well
  assert(r);
  assertEquals(r.path, "source[?].constructor");
});

// ── 3. privacy ──

Deno.test("422 contains-user-data: preset-name table, user cab banks, reserved special tables", () => {
  for (const id of [0xffff, 0xfff3, 0xfffe, 0xff00, 0xffef]) {
    assertEquals(outcome(ec((s) => (s.records[5].id = id))), "422 contains-user-data", id.toString(16));
    assertEquals(outcome(lv((s) => (s.records[0].id = id))), "422 contains-user-data", id.toString(16));
  }
  assert(isUserNameTable(0xffff));
  assertFalse(isUserNameTable(0xfff0));
  assertFalse(isUserNameTable(0xfff2));
});

Deno.test("422 tolerant-source: an editor cache with issues (even an empty list)", () => {
  assertEquals(outcome(ec((s) => (s.issues = [{ section: 7, record: 3, offset: 1000, reason: "x", droppedRecords: 1, skippedBytes: 32, resumedAt: 1032 }]))), "422 tolerant-source");
  assertEquals(outcome(ec((s) => (s.issues = []))), "422 tolerant-source");
  // `issues` is not a live field: dropped, never stored
  const r = parseContribution(lv((s) => (s.issues = []))!, CONSENT_NOW, NO_FLOOR);
  assert(r.ok);
  assertFalse("issues" in (r.value.source as Json));
});

// ── 4. shape ──

Deno.test("shape: kind and space", () => {
  assertEquals(outcome(ec((s) => (s.kind = "live-readonly"), { kind: "editor-cache" })), "422 invalid-source @source.kind");
  assertEquals(outcome(ec((s) => (s.space = "block"))), "422 invalid-source @source.space");
  assertEquals(outcome(lv((s) => (s.space = "section"))), "422 invalid-source @source.space");
  assertEquals(outcome(lv((s) => (s.kind = "live-full"))), "ok"); // the envelope follows the source's kind
  assertEquals(outcome(lv((s) => (s.kind = "live-full"), { kind: "live-readonly" })), "422 invalid-source @source.kind");
});

Deno.test("shape: record fields typed and bounded", () => {
  assertEquals(outcome(ec((s) => (s.records = {}))), "422 invalid-source @source.records");
  assertEquals(outcome(ec((s) => (s.records[0].kind = "int"))), "422 invalid-source @source.records[0].kind");
  assertEquals(outcome(ec((s) => (s.records[0].id = -1))), "422 invalid-source @source.records[0].id");
  assertEquals(outcome(ec((s) => (s.records[0].id = 1.5))), "422 invalid-source @source.records[0].id");
  assertEquals(outcome(ec((s) => (s.records[0].id = "3"))), "422 invalid-source @source.records[0].id");
  assertEquals(outcome(ec((s) => (s.records[0].tc = 0x10000))), "422 invalid-source @source.records[0].tc");
  assertEquals(outcome(ec((s) => (s.records[0].min = 4e38))), "422 invalid-source @source.records[0].min");
  assertEquals(outcome(ec((s) => (s.records[0].def = null))), "422 invalid-source @source.records[0].def");
  assertEquals(outcome(ec((s) => (s.records[0].t1 = -3))), "422 invalid-source @source.records[0].t1");
  assertEquals(outcome(ec((s) => (s.records[0].unit = "dB; drop"))), "422 invalid-source @source.records[0].unit");
  assertEquals(outcome(ec((s) => (s.records[0].placeholder = "yes"))), "422 invalid-source @source.records[0].placeholder");
  assertEquals(outcome(ec((s) => (s.records[0].taper = { shape: "cubic", err: null, reliable: true, points: [] }))), "422 invalid-source @source.records[0].taper.shape");
  assertEquals(outcome(ec((s) => (s.records[0].taper = { shape: "log", err: null, reliable: true, points: [[0, 1, 2]] }))), "422 invalid-source @source.records[0].taper.points[0]");
  assertEquals(outcome(ec((s) => (s.records = new Array(SOURCE_LIMITS.records + 1).fill(s.records[0])))), "422 invalid-source @source.records");
});

Deno.test("shape: enum count, labels, wire ids", () => {
  const enumAt = (s: Json) => s.records.findIndex((r: Json) => r.kind === "enum");
  const i = enumAt(editorCacheFixture());
  assertEquals(outcome(ec((s) => (s.records[i].count += 1))), `422 invalid-source @source.records[${i}].count`);
  assertEquals(outcome(ec((s) => (s.records[i].values[0] = "x".repeat(256)))), `422 invalid-source @source.records[${i}].values[0]`);
  assertEquals(outcome(ec((s) => (s.records[i].values[0] = "OK\u0007"))), `422 invalid-source @source.records[${i}].values[0]`);
  assertEquals(outcome(ec((s) => (s.records[i].values[0] = "\ud800"))), `422 invalid-source @source.records[${i}].values[0]`);
  assertEquals(outcome(ec((s) => (s.records[i].values[0] = 5))), `422 invalid-source @source.records[${i}].values[0]`);
  assertEquals(outcome(ec((s) => (s.records[i].wireIds = [1, 2]))), `422 invalid-source @source.records[${i}].wireIds`);
  // a factory bank table (0xfff0..0xfff2) may carry wire ids
  assertEquals(outcome(ec((s) => {
    Object.assign(s.records[i], { id: 0xfff0, wireIds: s.records[i].values.map((_: unknown, k: number) => 1000 + k) });
  })), "ok");
  // a live enum's count follows its range, its labels a separate walk: they may differ
  const j = liveFixture().records.findIndex((r: Json) => r.kind === "enum");
  assertEquals(outcome(lv((s) => (s.records[j].values = []))), "ok");
});

Deno.test("isValidLabel: ≤ 255 UTF-8 bytes, no C0/DEL, no lone surrogate", () => {
  assert(isValidLabel(""));
  assert(isValidLabel("x".repeat(255)));
  assertFalse(isValidLabel("x".repeat(256)));
  assert(isValidLabel("é".repeat(127)));
  assertFalse(isValidLabel("é".repeat(128)));
  assert(isValidLabel("🎸 Ω µ °"));
  assertFalse(isValidLabel("a\nb"));
  assertFalse(isValidLabel("a\u007fb"));
  assertFalse(isValidLabel("\udc00"));
});

Deno.test("shape: editor-cache sections and header", () => {
  assertEquals(outcome(ec((s) => s.sections.push({ tag: 7, count: 0 }))), "422 invalid-source @source.sections[5].tag");
  assertEquals(outcome(ec((s) => (s.records[0].section = 99))), "422 invalid-source @source.records[0].section");
  assertEquals(outcome(ec((s) => (s.header = null))), "422 invalid-source @source.header");
  assertEquals(outcome(ec((s) => (s.header.sectionCount = 6))), "422 invalid-source @source.header.sectionCount");
  assertEquals(outcome(ec((s) => (s.omitted.records = 0))), "422 invalid-source @source.sections");
  assertEquals(outcome(ec((s) => {
    // the sums still add up, but section 7 is declared smaller than its records
    s.sections[1].count -= 1;
    s.sections[2].count += 1;
  })), "422 invalid-source @source.sections[1].count");
  assertEquals(outcome(ec((s) => (s.fileVersion = "12.00"))), "422 invalid-source @source.fileVersion");
  assertEquals(outcome(ec((s) => (s.codecVersion = "1.0\n"))), "422 invalid-source @source.codecVersion");
  assertEquals(outcome(ec((s) => (s.codecVersion = "x".repeat(65)))), "422 invalid-source @source.codecVersion");
});

Deno.test("shape: live scope and walk", () => {
  assertEquals(outcome(lv((s) => (s.records[0].section = 1))), "422 invalid-source @source.records[0].section");
  assertEquals(outcome(lv((s) => (s.records[0].id = 16384))), "422 invalid-source @source.records[0].id");
  assertEquals(outcome(lv((s) => (s.scope.maxParamId = 512))), "422 invalid-source @source.scope.maxParamId");
  assertEquals(outcome(lv((s) => (s.scope.bounds["66"] = 600))), '422 invalid-source @source.scope.bounds["66"]');
  assertEquals(outcome(lv((s) => (s.scope.bounds["__x"] = 1))), "422 invalid-source @source.scope.bounds");
  assertEquals(outcome(lv((s) => (s.scope.bounds["300"] = 1))), "422 invalid-source @source.scope.bounds");
  assertEquals(outcome(lv((s) => (s.scope.idLists["70"] = new Array(257).fill(130)))), '422 invalid-source @source.scope.idLists["70"]');
  assertEquals(outcome(lv((s) => s.scope.blocks.push(256))), "422 invalid-source @source.scope.blocks[4]");
  assertEquals(outcome(lv((s) => s.scope.blocks.push(70))), "422 invalid-source @source.scope.blocks");
  assertEquals(outcome(lv((s) => (s.scope.hinted = "yes"))), "422 invalid-source @source.scope.hinted");
  assertEquals(outcome(lv((s) => (s.walk.queries = -1))), "422 invalid-source @source.walk.queries");
  assertEquals(outcome(lv((s) => (s.walk.extension = "partial"))), "422 invalid-source @source.walk.extension");
  assertEquals(outcome(lv((s) => (s.walk.boundHits = [{ block: 66, lastReal: 1 }]))), "422 invalid-source @source.walk.boundHits[0].bound");
  assertEquals(outcome(lv((s) => delete s.scope.idLists)), "ok");
});

Deno.test("shape: a (section, id) repeated with different content", () => {
  assertEquals(outcome(ec((s) => {
    s.records.push({ ...structuredClone(s.records[2]), max: 7 });
    s.sections[1].count += 1;
  })), "422 invalid-source @source.records[225]");
  // identical repeats are harmless (kept, so the section counts still add up)
  assertEquals(outcome(ec((s) => {
    s.records.push(structuredClone(s.records[2]));
    s.sections[1].count += 1;
  })), "ok");
});

// ── 5. consistency ──

Deno.test("422 firmware-inconsistent: the source's firmware is not the envelope's", () => {
  assertEquals(outcome(envelope(editorCacheFixture(), { firmware: "13.0" })), "422 firmware-inconsistent");
  assertEquals(outcome(ec((s) => (s.firmware = null))), "422 firmware-inconsistent");
  assertEquals(outcome(lv((s) => (s.firmware = "12.1"), { firmware: "12.0" })), "422 firmware-inconsistent");
});

Deno.test("422 version-mismatch: the file name's version is not the header's (a renamed file)", () => {
  assertEquals(outcome(ec((s) => (s.fileVersion = "13.0"))), "422 version-mismatch");
  // no file name version is fine; a header of another firmware than the device's is quality 2, not an error
  assertEquals(outcome(ec((s) => (s.fileVersion = null))), "ok");
  assertEquals(outcome(ec((s) => {
    s.firmware = "13.0";
    s.fileVersion = null;
  }, { firmware: "13.0" })), "ok");
});

// ── 6. plausibility floor ──

Deno.test("422 implausible: below the floor (the fixtures themselves are)", () => {
  assertEquals(PLAUSIBILITY_FLOOR, { editorCache: { sections: 16, records: 500 }, live: { blocks: 20, records: 300 } });
  const r = parseContribution(envelope(editorCacheFixture()), CONSENT_NOW);
  assertFalse(r.ok);
  // counted: the 4 sections that carry records (the 5th holds only the omitted preset-name table), 225 records
  assertEquals([r.status, r.error, r.fields.sections, r.fields.records], [422, "implausible", 4, 225]);
  assertEquals(outcome(envelope(liveFixture()), {}), "422 implausible");
  // enough sections but too few records, and the other way round
  const fewRecords = bigEditorCache();
  assertEquals(outcome(envelope(fewRecords), {}), "ok");
  assertEquals(outcome(envelope(fewRecords), { floor: { ...PLAUSIBILITY_FLOOR, editorCache: { sections: 16, records: 10_000 } } }), "422 implausible");
  const fewBlocks = bigLive();
  assertEquals(outcome(envelope(fewBlocks), { floor: { ...PLAUSIBILITY_FLOOR, live: { blocks: 40, records: 300 } } }), "422 implausible");
});

Deno.test("errors never echo a value from the source", () => {
  const secret = "VALUE-THAT-MUST-NOT-COME-BACK";
  const bodies = [
    ec((s) => (s.records[5].values[0] = secret + "\u0001")),
    ec((s) => (s.records[0].unit = secret)),
    ec((s) => (s.codecVersion = secret + "\n")),
    ec((s) => (s.fileVersion = secret)),
    lv((s) => (s.walk.extension = secret)),
    // an own "__proto__" key under a free-text key, as JSON.parse creates it
    ec((s) => (s.extra = JSON.parse(`{"${secret}":{"__proto__":1}}`)))
  ];
  for (const b of bodies) {
    const r = parseContribution(b, CONSENT_NOW, NO_FLOOR);
    assertFalse(r.ok);
    assertFalse(JSON.stringify(r).includes(secret), JSON.stringify(r));
  }
});

// ── small parsers ──

Deno.test("parseListQuery", () => {
  const q = (s: string) => parseListQuery(new URLSearchParams(s));
  assertEquals(q("model=17&firmware=13.0"), { ok: true, value: { model: 17, firmware: "13.0", rawFormat: 1 } });
  assertEquals(q("model=17&firmware=013.00&rawFormat=1"), { ok: true, value: { model: 17, firmware: "13.0", rawFormat: 1 } });
  assertEquals(q("model=18&firmware=12.0&rawFormat=7"), { ok: true, value: { model: 18, firmware: "12.0", rawFormat: 7 } });
  for (const bad of ["firmware=13.0", "model=999&firmware=13.0", "model=17", "model=17&firmware=x", "model=17&firmware=13.0&rawFormat=0", "model=17&firmware=13.0&rawFormat=abc"]) {
    const r = q(bad);
    assertFalse(r.ok, bad);
    assertEquals(r.status, 400);
  }
  assertEquals(normalizeFirmware("13.00"), "13.0");
  assertEquals(normalizeFirmware("1234.0"), null);
});

Deno.test("parseWithdrawRequest", () => {
  const id = "0000AAAA-0000-4000-8000-000000000001";
  assertEquals(parseWithdrawRequest({ sourceId: id }), { ok: true, value: { sourceId: id.toLowerCase() } });
  assertEquals(parseWithdrawRequest({ all: true }), { ok: true, value: { all: true, model: null, firmware: null } });
  assertEquals(parseWithdrawRequest({ all: true, model: 17, firmware: "13.00" }), { ok: true, value: { all: true, model: 17, firmware: "13.0" } });
  for (const bad of [null, {}, { sourceId: id, all: true }, { sourceId: "x" }, { all: false }, { all: "yes" }, { all: true, model: 300 }, { all: true, firmware: "x" }, { sourceId: id, model: 17 }]) {
    const r = parseWithdrawRequest(bad);
    assertFalse(r.ok, JSON.stringify(bad));
    assertEquals(r.status, 400);
  }
});

Deno.test("parseReportRequest", () => {
  const id = "00000000-0000-4000-8000-000000000001";
  const ok = { sourceId: id, verdict: "passed", checked: 24, answered: 23, mismatches: 0, app: { forgefx: "0.11.0", x: "y" } };
  assertEquals(parseReportRequest(ok), { ok: true, value: { ...ok, verdict: "passed", app: { forgefx: "0.11.0" } } });
  assert(parseReportRequest({ ...ok, verdict: "failed", mismatches: 2 }).ok);
  for (const bad of [
    { ...ok, sourceId: "nope" },
    { ...ok, verdict: "inconclusive" },
    { ...ok, checked: 65 },
    { ...ok, answered: 25 },
    { ...ok, mismatches: 1 },
    { ...ok, verdict: "failed" },
    { ...ok, checked: 1.5 },
    "x"
  ]) {
    const r = parseReportRequest(bad);
    assertFalse(r.ok, JSON.stringify(bad));
    assertEquals(r.status, 400);
  }
});

// ── review fixes: padding, codec version, report plausibility, the network-key secret ──

Deno.test("422 implausible: identical repeats do not count (16 sections x 32 copies of one record)", () => {
  const s = editorCacheFixture();
  const rec = s.records[0];
  s.records = [];
  s.sections = [];
  for (let t = 1; t <= 16; t++) {
    for (let i = 0; i < 32; i++) s.records.push({ ...rec, section: t });
    s.sections.push({ tag: t, count: 32 });
  }
  s.omitted = { tables: 0, records: 0 };
  s.header.sectionCount = 16;
  assertEquals(outcome(envelope(s)), "ok", "structurally fine (floor off): repeats are allowed");
  const r = parseContribution(envelope(s), CONSENT_NOW);
  assertFalse(r.ok);
  assertEquals([r.status, r.error, r.fields.sections, r.fields.records], [422, "implausible", 16, 16]);
});

Deno.test("422 implausible: sections without records do not count towards the floor", () => {
  // 600 distinct records, all in ONE section, plus 15 empty declared sections
  const s = editorCacheFixture();
  const seed = s.records[0];
  s.records = Array.from({ length: 600 }, (_, i) => ({ ...seed, id: i }));
  s.sections = [{ tag: 7, count: 600 }, ...Array.from({ length: 15 }, (_, i) => ({ tag: 200 + i, count: 0 }))];
  s.omitted = { tables: 0, records: 0 };
  s.header.sectionCount = 16;
  const r = parseContribution(envelope(s), CONSENT_NOW);
  assertFalse(r.ok);
  assertEquals([r.error, r.fields.sections, r.fields.records], ["implausible", 1, 600]);
});

Deno.test("422 implausible: a live scope listing blocks without records gains nothing", () => {
  // the 4 record-carrying blocks of the fixture, padded to 30 declared blocks and repeated records
  const s = liveFixture();
  for (let b = 200; b < 226; b++) s.scope.blocks.push(b);
  s.records = [...s.records, ...s.records.map((r: Json) => structuredClone(r))];
  const r = parseContribution(envelope(s), CONSENT_NOW);
  assertFalse(r.ok);
  assertEquals([r.error, r.fields.blocks, r.fields.records], ["implausible", 4, 225]);
});

Deno.test("codecVersion must be a version stamp", () => {
  for (const v of ["0.0.0-fixture", "0.12.0", "0.12.0-beta.1", "1.0.0+build.5", "10.2.33-rc.1+sha.abc"]) {
    assertEquals(outcome(ec((s) => (s.codecVersion = v))), "ok", v);
  }
  for (const v of ["", "1.0", "x", "0.12.0 beta", "../../etc", "01.2.3", "0.12.0-", `1.0.0-${"a".repeat(60)}`, "dev build"]) {
    assertEquals(outcome(ec((s) => (s.codecVersion = v))), "422 invalid-source @source.codecVersion", v);
  }
});

Deno.test("parseReportRequest: plausible outcomes only", () => {
  const id = "00000000-0000-4000-8000-000000000001";
  const rep = (verdict: string, checked: number, answered: number, mismatches: number) =>
    parseReportRequest({ sourceId: id, verdict, checked, answered, mismatches }).ok;
  assert(rep("passed", 24, 22, 0), "22/24 is >= 90 %");
  assert(rep("passed", 12, 11, 0), "11/12 is >= 90 %");
  assert(rep("passed", 20, 18, 0), "exactly 90 %");
  assertFalse(rep("passed", 24, 21, 0), "21/24 is below 90 %");
  assertFalse(rep("passed", 11, 11, 0), "fewer than 12 targets");
  assertFalse(rep("passed", 0, 0, 0), "an empty check");
  assert(rep("failed", 24, 1, 1), "one answered mismatch is a failure");
  assert(rep("failed", 3, 2, 1), "a check stopped early with a mismatch still failed");
  assertFalse(rep("failed", 24, 0, 1), "a failure needs an answer");
});

Deno.test("resolveIpSalt: missing, short, or the editor-cache secret -> no salt (writes paused)", () => {
  const good = "s".repeat(32);
  assertEquals(resolveIpSalt(good, "e".repeat(40)), { salt: good, problem: null });
  assertEquals(resolveIpSalt(good, undefined), { salt: good, problem: null });
  assertEquals(resolveIpSalt(undefined, undefined), { salt: null, problem: "missing" });
  assertEquals(resolveIpSalt("", "x"), { salt: null, problem: "missing" });
  assertEquals(resolveIpSalt("s".repeat(31), undefined), { salt: null, problem: "short" });
  assertEquals(resolveIpSalt(good, good), { salt: null, problem: "shared" });
  assertEquals(resolveIpSalt(good, ` ${good}\n`), { salt: null, problem: "shared" });
});
