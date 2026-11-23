// Synthetic shared sources for the definition-sources tests. Built ONLY from the codec's synthetic golden fixtures
// (fixtures/*.json, copied verbatim from the public forgefx-midi repository; themselves built from committed
// catalog rows) — never from real device reads, captures or stored rows.
import editorCacheJson from "./fixtures/editor-cache.source.json" with { type: "json" };
import factHashesJson from "./fixtures/fact-hashes.json" with { type: "json" };
import liveReadonlyJson from "./fixtures/live-readonly.source.json" with { type: "json" };

// deno-lint-ignore no-explicit-any
export type Json = any;

const clone = <T>(v: T): T => structuredClone(v);

/** The golden vectors (canonicalJson, sources, tiny). */
export const GOLDENS: Json = factHashesJson;

/** The editor-cache fixture (FM3 = 17, firmware 12.0; 5 sections, 225 records): below the plausibility floor. */
export function editorCacheFixture(): Json {
  return clone(editorCacheJson);
}

/** The live read-only fixture (FM3, 12.0; 4 blocks, 225 records): below the plausibility floor. */
export function liveFixture(): Json {
  return clone(liveReadonlyJson);
}

/** Distinct sections / blocks that carry records (what the plausibility floor counts). */
const carrying = (records: Json[]) => new Set(records.map((r: Json) => r.section)).size;

/**
 * The editor-cache fixture grown past the plausibility floor: the records of its first record-carrying section are
 * repeated under new section tags (100, 101, …) until ≥ 16 sections carry records and there are ≥ 500 distinct
 * records; header and section list follow, so it stays self-consistent (quality 3).
 */
export function bigEditorCache(): Json {
  const s = editorCacheFixture();
  const seed = s.records.filter((r: Json) => r.section === s.records[0].section);
  let tag = 100;
  while (carrying(s.records) < 16 || s.records.length < 500) {
    for (const r of seed) s.records.push({ ...clone(r), section: tag });
    s.sections.push({ tag, count: seed.length });
    tag++;
  }
  s.header.sectionCount = s.sections.length;
  return s;
}

/** The live fixture grown past the floor the same way (new blocks 100, 101, … added to scope.blocks). */
export function bigLive(): Json {
  const s = liveFixture();
  const first = s.scope.blocks[0];
  const seed = s.records.filter((r: Json) => r.section === first);
  let block = 100;
  while (carrying(s.records) < 20 || s.records.length < 300) {
    for (const r of seed) s.records.push({ ...clone(r), section: block });
    s.scope.blocks.push(block);
    block++;
  }
  return s;
}

export const CONSENT_NOW = Date.parse("2026-12-01T10:00:00Z");

/** A contribution request around `source` (FM3, the source's firmware, consent given now). */
export function envelope(source: Json, overrides: Record<string, unknown> = {}): Json {
  return {
    model: 17,
    firmware: source?.firmware ?? "12.0",
    kind: source?.kind,
    rawFormat: 1,
    source,
    app: { forgefx: "0.11.0", codec: "0.12.0-beta", axis: "0.11.0" },
    consentAt: new Date(CONSENT_NOW - 60_000).toISOString(),
    consentVersion: 1,
    ...overrides
  };
}
