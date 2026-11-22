// Unit tests for editor-caches/validate.ts: the editor-cache structure/redaction check, the network key, and
// request validation. Run with:
//   deno test supabase/functions/editor-caches/
// Synthetic caches only (synthetic-cache.ts) — never real files.
import { assert, assertEquals, assertMatch, assertNotEquals } from "jsr:@std/assert@1";
import {
  blank,
  cache,
  enumRec,
  FACTORY_CAB_NAMES,
  fillerSections,
  floatRec,
  PRESET_NAMES,
  section,
  tableRec,
  TYPICAL,
  typicalCache,
  USER_CAB_NAMES
} from "./synthetic-cache.ts";
import {
  type CacheCheckOptions,
  clientNetwork,
  describeClientHeaders,
  isUserNameTable,
  MAX_UPLOAD_BYTES,
  MIN_CONSENT_VERSION,
  networkKey,
  normalizeFirmware,
  parseEditorCacheName,
  parseRedaction,
  parseReserveRequest,
  parseStatusQuery,
  parseUploadIdRequest,
  PLAUSIBILITY_FLOOR,
  sanitizeApp,
  sanitizeSummary,
  validateEditorCache
} from "./validate.ts";

const V13 = { fileVersion: "13.0", contentVersion: null };

/** Structure + redaction only (no plausibility floor), so small hand-built caches can probe single rules. */
function reason(buf: Uint8Array, claims: { fileVersion: string; contentVersion: string | null } = V13, opts: CacheCheckOptions = {}) {
  const r = validateEditorCache(buf, claims, { floor: null, ...opts });
  return r.ok ? "ok" : r.reason;
}

/** The full check, as the server runs it (with the plausibility floor). */
function fullReason(buf: Uint8Array, claims: { fileVersion: string; contentVersion: string | null } = V13) {
  const r = validateEditorCache(buf, claims);
  return r.ok ? "ok" : r.reason;
}

// ── user-name tables ──

Deno.test("isUserNameTable: preset names, user/scratchpad cab banks and the reserved range; not factory banks", () => {
  assert(isUserNameTable(0xffff));
  for (let id = 0xfff3; id <= 0xfffe; id++) assert(isUserNameTable(id), id.toString(16));
  for (const id of [0xff00, 0xff10, 0xffef]) assert(isUserNameTable(id), id.toString(16));
  for (const id of [0xfff0, 0xfff1, 0xfff2, 0xfeff, 0x0000, 0x0001, 0x1234]) assert(!isUserNameTable(id), id.toString(16));
});

// ── structure check: accepted files ──

Deno.test("a redacted cache passes the full check (incl. the plausibility floor) and reports its shape", () => {
  const r = validateEditorCache(typicalCache(13, 0, true), V13);
  assert(r.ok, JSON.stringify(r));
  assertEquals(r.headerVersion, "13.0");
  assertEquals(r.sections, TYPICAL.sections);
  assertEquals(r.records, TYPICAL.records);
  assertEquals(r.userNameTables, 2);
  // non-empty user names: 2 cab names + 4 preset names (empty entries stay empty and are not counted)
  assertEquals(r.userNames, 6);
  assertEquals(r.presetNameTable, true);
  assert(typicalCache().length >= PLAUSIBILITY_FLOOR.minBytes);
});

// ── plausibility floor ──

Deno.test("the floor is far below real caches (278–329 KB, 45–57 sections, ~2,500 records)", () => {
  assertEquals(PLAUSIBILITY_FLOOR, { minBytes: 32 * 1024, minSections: 16, minRecords: 500, requirePresetNameTable: true });
});

Deno.test("a tiny but structurally valid file is implausible (it must not be able to cover a firmware)", () => {
  const tiny = cache(13, 0, [section(40, [enumRec(0xffff, [blank("x")])])]);
  assertEquals(reason(tiny), "ok", "structure and redaction alone would accept it");
  assertEquals(fullReason(tiny), "implausible");
});

Deno.test("too few sections, too few records, or no preset-name table is implausible", () => {
  const presets = section(40, [enumRec(0xffff, [blank("Preset")])]);
  // big enough, many records, but only 2 sections
  const fewSections = cache(13, 0, [presets, section(1, Array.from({ length: 1200 }, (_, i) => floatRec(i)))]);
  assert(fewSections.length >= PLAUSIBILITY_FLOOR.minBytes);
  assertEquals(fullReason(fewSections), "implausible");
  // big enough (long names), many sections, but few records
  const longNames = Array.from({ length: 10 }, (_, i) => `${i}`.padEnd(200, "n"));
  const fewRecords = cache(13, 0, [presets, ...Array.from({ length: 20 }, (_, s) => section(100 + s, [enumRec(1, longNames)]))]);
  assert(fewRecords.length >= PLAUSIBILITY_FLOOR.minBytes);
  assertEquals(fullReason(fewRecords), "implausible");
  // everything but the preset-name table
  const noPresets = cache(13, 0, [section(1, [floatRec(0)]), ...fillerSections(20, 55)]);
  assertEquals(reason(noPresets), "ok");
  assertEquals(fullReason(noPresets), "implausible");
  // the preset-name table counts even when its (empty) list makes it a float-tailed record
  const emptyPresets = cache(13, 0, [section(40, [floatRec(0xffff)]), ...fillerSections(20, 55)]);
  assertEquals(fullReason(emptyPresets), "ok");
});

Deno.test("a header build date and odd header bytes are ignored; minor versions above 9 work", () => {
  assertEquals(reason(typicalCache(12, 0, true, { buildDate: "Jan 01 2026 00:00:00" }), { fileVersion: "12.0", contentVersion: null }), "ok");
  assertEquals(reason(typicalCache(28, 247, true), { fileVersion: "28.247", contentVersion: null }), "ok");
});

Deno.test("a matching claimed content version is accepted", () => {
  assertEquals(reason(typicalCache(13, 0, true), { fileVersion: "13.0", contentVersion: "13.0" }), "ok");
});

Deno.test("empty user names and an unused (all-empty) user bank count as redacted", () => {
  const buf = cache(13, 0, [
    section(11, [tableRec(0xfff3, ["", "", ""], [0, 0, 0]), tableRec(0xfff4, ["", blank("abc")], [1, 2])]),
    section(40, [enumRec(0xffff, [blank("First"), "", ""])])
  ]);
  const r = validateEditorCache(buf, V13, { floor: null });
  assert(r.ok);
  assertEquals(r.userNameTables, 3);
  assertEquals(r.userNames, 2);
});

Deno.test("factory bank names and non-ASCII names in ordinary records are not user names", () => {
  const buf = cache(13, 0, [
    section(1, [enumRec(5, ["Größe", "Room: Small"])]),
    section(11, [tableRec(0xfff1, FACTORY_CAB_NAMES, [1, 2, 3]), tableRec(0xfff2, ["Legacy 1"], [9])])
  ]);
  assertEquals(reason(buf), "ok");
});

// ── structure check: redaction ──

Deno.test("unredacted preset names are refused (not-redacted), without echoing them", () => {
  const r = validateEditorCache(typicalCache(13, 0, false), V13); // full check: redaction is reported first
  assert(!r.ok);
  assertEquals(r.reason, "not-redacted");
  for (const n of [...PRESET_NAMES, ...USER_CAB_NAMES].filter(Boolean)) assert(!r.detail.includes(n), "detail must not quote names");
});

Deno.test("one unredacted user cab name is enough to refuse; a partly blanked name too", () => {
  const cab = cache(13, 0, [section(11, [tableRec(0xfff3, ["", blank("one"), "two"], [1, 2, 3])])]);
  assertEquals(reason(cab), "not-redacted");
  const partly = cache(13, 0, [section(40, [enumRec(0xffff, ["___a_"])])]);
  assertEquals(reason(partly), "not-redacted");
  const utf8 = cache(13, 0, [section(40, [enumRec(0xffff, ["Grüße"])])]);
  assertEquals(reason(utf8), "not-redacted");
});

Deno.test("a record in the reserved range is held to the redaction rule as well", () => {
  assertEquals(reason(cache(13, 0, [section(2, [enumRec(0xff10, ["Something"])])])), "not-redacted");
  assertEquals(reason(cache(13, 0, [section(2, [enumRec(0xff10, [blank("Something")])])])), "ok");
});

// ── structure check: header ──

Deno.test("the header version must equal the file version (and a claimed content version)", () => {
  const buf = typicalCache(13, 0, true);
  assertEquals(reason(buf, { fileVersion: "12.0", contentVersion: null }), "version-mismatch");
  assertEquals(reason(buf, { fileVersion: "13.0", contentVersion: "12.0" }), "version-mismatch");
  assertEquals(reason(typicalCache(76, 0, true), { fileVersion: "12.0", contentVersion: null }), "version-mismatch");
});

Deno.test("an implausible header version is refused", () => {
  assertEquals(reason(typicalCache(0, 0, true), { fileVersion: "0.0", contentVersion: null }), "header-version");
  assertEquals(reason(typicalCache(1000, 0, true), { fileVersion: "1000.0", contentVersion: null }), "header-version");
  assertEquals(reason(typicalCache(13, 1000, true), { fileVersion: "13.1000", contentVersion: null }), "header-version");
});

Deno.test("the header section count must be plausible and equal the walk", () => {
  assertEquals(reason(typicalCache(13, 0, true, { declaredSections: 4 })), "section-count");
  assertEquals(reason(typicalCache(13, 0, true, { declaredSections: 2 })), "section-count");
  assertEquals(reason(typicalCache(13, 0, true, { declaredSections: 0 })), "section-count");
  assertEquals(reason(typicalCache(13, 0, true, { declaredSections: 5000 })), "section-count");
});

// ── structure check: damaged / foreign files ──

Deno.test("truncated files are refused (mid-record, and at a record boundary short of the declared count)", () => {
  const good = typicalCache(13, 0, true);
  assertEquals(reason(good.subarray(0, good.length - 5)), "structure");
  // the last section declares one record more than the file holds; the file ends right after a record
  const short = cache(13, 0, [section(1, [floatRec(0)]), section(2, [floatRec(1), floatRec(2)], 3)]);
  assertEquals(reason(short), "structure");
});

Deno.test("trailing bytes after the last section are refused", () => {
  const good = typicalCache(13, 0, true);
  const tail = new Uint8Array(good.length + 3);
  tail.set(good);
  assertEquals(reason(tail), "structure");
});

Deno.test("a non-zero record padding is refused", () => {
  const buf = cache(13, 0, [section(1, [floatRec(0), floatRec(1)])]);
  buf[0x2e + 8 + 32 + 4] = 1; // pad of the second record
  assertEquals(reason(buf), "structure");
});

Deno.test("the older cache revision marker is refused", () => {
  const buf = cache(13, 0, [section(1, [floatRec(0)]), [0, 0, 0, 0, 0, 0, 0, 0x80]], { declaredSections: 2 });
  assertEquals(reason(buf), "structure");
});

Deno.test("a file with the short (0x0e) preamble or no section at 0x2e is refused", () => {
  const sec = section(1, [floatRec(0), floatRec(1)]);
  const short = new Uint8Array(0x0e + sec.length);
  short.set([13, 0, 0, 0], 0);
  short.set(sec, 0x0e);
  assertNotEquals(reason(short), "ok");
  const zeros = cache(13, 0, [], { declaredSections: 1 });
  const padded = new Uint8Array(zeros.length + 40);
  padded.set(zeros);
  assertEquals(reason(padded), "structure");
});

Deno.test("too small or above the cap is refused (size)", () => {
  assertEquals(reason(new Uint8Array(10)), "size");
  assertEquals(reason(new Uint8Array(0x2e + 7)), "size");
  assertEquals(reason(typicalCache(13, 0, true), V13, { maxBytes: 64 }), "size");
});

Deno.test("a control byte inside a user name breaks the structure (it can never be smuggled as a name)", () => {
  assertNotEquals(reason(cache(13, 0, [section(40, [enumRec(0xffff, ["__\u0001__"])])])), "ok");
});

Deno.test("the work budget stops pathological walks", () => {
  assertEquals(reason(typicalCache(13, 0, true), V13, { budget: 20 }), "too-complex");
});

Deno.test("never throws on garbage or random mutations of a valid file", () => {
  let seed = 0x12345678;
  const rnd = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) / 0x100000000;
  };
  const base = typicalCache(13, 0, true);
  for (let i = 0; i < 2000; i++) {
    const buf = base.slice();
    const flips = 1 + Math.floor(rnd() * 4);
    for (let k = 0; k < flips; k++) buf[Math.floor(rnd() * buf.length)] = Math.floor(rnd() * 256);
    const r = validateEditorCache(buf, V13);
    assertEquals(typeof r.ok, "boolean");
  }
  for (let i = 0; i < 200; i++) {
    const buf = new Uint8Array(Math.floor(rnd() * 600));
    for (let k = 0; k < buf.length; k++) buf[k] = Math.floor(rnd() * 256);
    assertEquals(typeof validateEditorCache(buf, V13).ok, "boolean");
  }
});

// ── network key ──

function h(init: Record<string, string>): Headers {
  return new Headers(init);
}

Deno.test("clientNetwork: proxy-set headers first, only the LAST x-forwarded-for entry, IPv6 by /64", () => {
  assertEquals(clientNetwork(h({ "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "198.51.100.1" })), "v4:203.0.113.7");
  assertEquals(clientNetwork(h({ "x-real-ip": "203.0.113.8" })), "v4:203.0.113.8");
  // the first x-forwarded-for entries are whatever the client sent; the last one the nearest proxy appended
  assertEquals(clientNetwork(h({ "x-forwarded-for": "1.1.1.1, 198.51.100.9" })), "v4:198.51.100.9");
  assertEquals(clientNetwork(h({ "x-real-ip": "2001:db8:abcd:12:1:2:3:4" })), "v6:2001:db8:abcd:12");
  assertEquals(clientNetwork(h({ "x-real-ip": "2001:db8:abcd:12::99" })), "v6:2001:db8:abcd:12");
  assertEquals(clientNetwork(h({ "x-real-ip": "[2001:db8::1]:443" })), "v6:2001:db8:0:0");
  assertEquals(clientNetwork(h({ "x-real-ip": "::ffff:192.0.2.1" })), "v4:192.0.2.1");
  assertEquals(clientNetwork(h({ "x-real-ip": "192.0.2.1:5678" })), "v4:192.0.2.1");
  assertEquals(clientNetwork(h({ "x-real-ip": "not-an-ip" })), "unknown");
  assertEquals(clientNetwork(h({ "x-real-ip": "999.1.1.1" })), "unknown");
  assertEquals(clientNetwork(h({})), "unknown");
  // a deployment can name the header its own proxy sets
  assertEquals(clientNetwork(h({ "x-client-ip": "192.0.2.5", "cf-connecting-ip": "192.0.2.6" }), ["x-client-ip"]), "v4:192.0.2.5");
});

Deno.test("describeClientHeaders reports header names and the x-forwarded-for entry count, never values", () => {
  const d = describeClientHeaders(h({ "x-forwarded-for": "198.51.100.1, 203.0.113.7", "x-real-ip": "203.0.113.7", "x-other": "1" }));
  assertEquals(d, { present: ["x-real-ip", "x-forwarded-for"], xffEntries: 2 });
  assert(!JSON.stringify(d).includes("203.0.113.7"));
  assertEquals(describeClientHeaders(h({})), { present: [], xffEntries: 0 });
  assertEquals(describeClientHeaders(h({ "x-client-ip": "192.0.2.1" }), ["x-client-ip"]).present, ["x-client-ip"]);
});

Deno.test("networkKey: keyed, deterministic, 64 hex, never contains the address", async () => {
  const a = await networkKey("secret-1", "v4:203.0.113.7");
  assertMatch(a, /^[0-9a-f]{64}$/);
  assertEquals(a, await networkKey("secret-1", "v4:203.0.113.7"));
  assertNotEquals(a, await networkKey("secret-2", "v4:203.0.113.7"));
  assertNotEquals(a, await networkKey("secret-1", "v4:203.0.113.8"));
  assert(!a.includes("203"));
});

// ── request validation ──

const NOW = Date.parse("2026-11-23T10:00:00Z");
const SHA = "a".repeat(64);
const reserveBody = (over: Record<string, unknown> = {}) => ({
  model: 17,
  deviceFirmware: "13.0",
  fileVersion: "13.0",
  contentVersion: null,
  fileName: "effectDefinitions_11_13p0.cache",
  sha256: SHA,
  bytes: 279183,
  redaction: { version: 1, tables: 2, names: 1024 },
  summary: { sections: 45, records: 2503, unmappedSections: 0, suspectFamilies: [], newRows: 8, incompatibleRows: 2, agreement: 0.9988 },
  app: { forgefx: "0.9.0-beta", codec: "0.7.0", axis: "0.11.0-beta" },
  consentAt: "2026-11-23T09:59:00.000Z",
  consentVersion: MIN_CONSENT_VERSION,
  ...over
});

Deno.test("parseReserveRequest accepts the ForgeFX body and normalizes it", () => {
  const p = parseReserveRequest(reserveBody({ deviceFirmware: "013.00" }), NOW);
  assert(p.ok);
  assertEquals(p.value.deviceFirmware, "13.0");
  assertEquals(p.value.redaction, { version: 1, tables: 2, names: 1024 });
  assertEquals(p.value.consentAt, "2026-11-23T09:59:00.000Z");
  assertEquals(p.value.contentVersion, null);
});

Deno.test("parseReserveRequest refuses malformed fields", () => {
  const cases: Array<[string, Record<string, unknown>, number, string]> = [
    ["model string", { model: "17" }, 400, "invalid-request"],
    ["model range", { model: 256 }, 400, "invalid-request"],
    ["firmware shape", { deviceFirmware: "13" }, 400, "invalid-request"],
    ["file version missing", { fileVersion: null }, 400, "invalid-request"],
    ["content version shape", { contentVersion: "x" }, 400, "invalid-request"],
    ["file name path", { fileName: "../effectDefinitions_11_13p0.cache" }, 400, "invalid-request"],
    ["not an editor cache name", { fileName: "presets.syx" }, 400, "invalid-request"],
    ["name model mismatch", { fileName: "effectDefinitions_12_13p0.cache" }, 400, "invalid-request"],
    ["name version mismatch (renamed)", { fileName: "effectDefinitions_11_12p0.cache" }, 400, "invalid-request"],
    ["sha upper case", { sha256: "A".repeat(64) }, 400, "invalid-request"],
    ["sha short", { sha256: "abc" }, 400, "invalid-request"],
    ["bytes zero", { bytes: 0 }, 400, "invalid-request"],
    ["bytes over the cap", { bytes: MAX_UPLOAD_BYTES + 1 }, 413, "too-large"],
    ["redaction missing", { redaction: undefined }, 400, "invalid-request"],
    ["redaction extra key", { redaction: { version: 1, tables: 2, names: 3, bytesReplaced: 9 } }, 400, "invalid-request"],
    ["redaction version 0", { redaction: { version: 0, tables: 2, names: 3 } }, 400, "invalid-request"],
    ["redaction negative", { redaction: { version: 1, tables: -1, names: 3 } }, 400, "invalid-request"],
    ["consent missing", { consentAt: undefined }, 400, "consent-required"],
    ["consent version missing", { consentVersion: undefined }, 400, "consent-required"],
    ["consent not ISO", { consentAt: "yesterday" }, 400, "consent-required"],
    ["consent too old", { consentAt: "2026-11-21T09:00:00Z" }, 400, "consent-required"],
    ["consent in the future", { consentAt: "2026-11-25T09:00:00Z" }, 400, "consent-required"],
    ["consent version 0", { consentVersion: 0 }, 400, "consent-required"],
    ["consent to the older text (v1: accounts only)", { consentVersion: 1 }, 400, "consent-required"],
    ["consent version huge", { consentVersion: 40000 }, 400, "consent-required"]
  ];
  for (const [label, over, status, error] of cases) {
    const p = parseReserveRequest(reserveBody(over), NOW);
    assert(!p.ok, label);
    assertEquals([p.status, p.error], [status, error], label);
  }
  assert(!parseReserveRequest([], NOW).ok);
});

Deno.test("summary and app are sanitized to known keys", () => {
  assertEquals(
    sanitizeSummary({ sections: 45, records: -1, agreement: 2, suspectFamilies: ["AMP", "bad name", 7, "X".repeat(30)], evil: "x" }),
    { sections: 45, suspectFamilies: ["AMP"] }
  );
  const p = parseReserveRequest(reserveBody({ app: { forgefx: "1", path: "C:\\Users\\x" }, summary: "nope" }), NOW);
  assert(p.ok);
  assertEquals(p.value.app, { forgefx: "1" });
  assertEquals(p.value.summary, {});
  // version stamps only: free text (paths, names, spaces) is dropped
  assertEquals(
    sanitizeApp({ forgefx: "0.9.0-beta", codec: "C:\\Users\\someone", axis: "1.2.3+build.4" }),
    { forgefx: "0.9.0-beta", axis: "1.2.3+build.4" }
  );
  assertEquals(sanitizeApp({ forgefx: "my laptop", codec: "x".repeat(33), axis: "" }), {});
});

Deno.test("small parsers", () => {
  assertEquals(normalizeFirmware("12.0"), "12.0");
  assertEquals(normalizeFirmware("12"), null);
  assertEquals(parseEditorCacheName("effectDefinitions_11_13p0.cache"), { model: 0x11, version: "13.0" });
  assertEquals(parseEditorCacheName("effectDefinitions_10_32p6.cache"), { model: 0x10, version: "32.6" });
  assertEquals(parseEditorCacheName("effectDefinitions_11_13p0.cache.bak"), null);
  assertEquals(parseRedaction({ version: 1, tables: 0, names: 0 }), { version: 1, tables: 0, names: 0 });
  assertEquals(parseRedaction(null), null);
  assert(parseUploadIdRequest({ uploadId: "5B0E0000-0000-4000-8000-000000000001" }).ok);
  assert(!parseUploadIdRequest({ uploadId: "x" }).ok);
  const q = parseStatusQuery(new URLSearchParams("model=17&firmware=13.0"));
  assert(q.ok);
  assertEquals(q.value, { model: 17, firmware: "13.0" });
  assert(!parseStatusQuery(new URLSearchParams("model=300&firmware=13.0")).ok);
  assert(!parseStatusQuery(new URLSearchParams("model=17&firmware=13")).ok);
  assert(!parseStatusQuery(new URLSearchParams("model=-1&firmware=13.0")).ok);
});
