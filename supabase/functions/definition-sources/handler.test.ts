// Unit tests for the definition-sources edge function. Run with:
//   deno test supabase/functions/definition-sources/
// No Supabase stack or network is needed: handler.ts talks to the database only through `Deps`, which these tests
// replace with in-memory fakes. What they therefore do NOT cover — and what needs a local stack or a rolled-back
// staging run — is everything behind that seam: the SQL functions (ranking, tiers, limits, dedupe, locks; see
// supabase/tests/database/definition_sources.test.sql) and the Supabase adapter in index.ts. The fakes below only
// mimic the SQL semantics so the handler's mapping can be asserted. Synthetic sources only.
import { assert, assertEquals, assertFalse, assertMatch, assertNotEquals } from "jsr:@std/assert@1";
import { networkKey as editorCacheNetworkKey } from "../editor-caches/validate.ts";
import { networkKey } from "../_shared/network.ts";
import { sourceFactHash } from "./facts.ts";
import {
  type ContributeArgs,
  contributeOutcomeFromSqlError,
  type ContributeResult,
  type ContributionSummary,
  DEFAULT_CONFIG,
  type Deps,
  handleRequest,
  type HandlerConfig,
  ipDiagnostics,
  isAuthOutage,
  isServable,
  type ListedSourceRow,
  type ReportArgs,
  reportOutcomeFromSqlError,
  type SourceRow,
  type WithdrawArgs
} from "./handler.ts";
import { bigEditorCache, bigLive, CONSENT_NOW, editorCacheFixture, envelope, GOLDENS, type Json, liveFixture } from "./synthetic-sources.ts";
import { MAX_CONTRIBUTION_BYTES, NETWORK_DOMAIN } from "./validate.ts";

const USER = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const ANON = "33333333-3333-4333-8333-333333333333";
const TOKEN = "hdr.payload.user";
const TOKEN_OTHER = "hdr.payload.other";
const TOKEN_ANON = "hdr.payload.anon";
const TOKEN_UNKNOWN = "hdr.payload.unknown";
const TOKEN_AUTH_DOWN = "hdr.payload.authdown"; // the fake Auth server cannot answer for this one
const IP = "203.0.113.7";
const IP2 = "198.51.100.9";
const SALT = "test-salt-0123456789abcdef0123456789abcdef"; // ≥ 32 chars, like a real one must be
const NOW = CONSENT_NOW;
const DAY = 86_400_000;
const logged: Array<[string, string]> = [];
const CFG: HandlerConfig = { ...DEFAULT_CONFIG, ipSalt: SALT, now: () => NOW, log: (level, msg) => void logged.push([level, msg]) };
/** The codec fixtures are below the plausibility floor; most flow tests use them with the floor off. */
const SMALL: HandlerConfig = { ...CFG, validation: { floor: null } };
const BASE = "http://localhost/definition-sources";

// ── fakes (mimic the SQL; the SQL is authoritative — see the pgTAP file) ──

interface Src extends SourceRow {
  coverageScore: number;
  networks: number;
  spotPasses: number;
  spotFailures: number;
  bytes: number;
  firstSeen: number;
  lastConfirmed: number | null;
}
interface Contrib {
  id: string;
  sourceId: string;
  userId: string | null;
  networkKey: string | null;
  firstOfNetwork: boolean;
  model: number;
  firmware: string;
  kind: SourceRow["kind"];
  createdAt: number;
  linkedUntil: number;
}
interface Report {
  sourceId: string;
  userId: string;
  networkKey: string;
  verdict: "passed" | "failed";
}

const day = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString().slice(0, 10));
const TIER_RANK: Record<string, number> = { official: 0, verified: 1, candidate: 2 };

function makeDeps() {
  const sources: Src[] = [];
  const contribs: Contrib[] = [];
  const reports: Report[] = [];
  const usage: Array<{ key: string; action: "contribute" | "report" }> = [];
  const calls = { contribute: [] as ContributeArgs[], withdraw: [] as WithdrawArgs[], report: [] as ReportArgs[], select: [] as unknown[][], auth: 0, mine: [] as unknown[][] };
  const state = { seq: 0, force: null as ContributeResult | null, forceReport: null as Awaited<ReturnType<Deps["report"]>> | null, throwOn: null as string | null };
  const nextId = () => `00000000-0000-4000-8000-${String(++state.seq).padStart(12, "0")}`;

  const refresh = (s: Src) => {
    const mine = contribs.filter((c) => c.sourceId === s.id);
    s.contributors = mine.length;
    s.networks = mine.filter((c) => c.firstOfNetwork).length;
    if (!s.pinned) s.tier = s.quality === 3 && s.contributors >= 2 && s.networks >= 2 ? "verified" : "candidate";
    s.quarantined = s.tier === "candidate" && !s.pinned && s.spotFailures >= 3 && s.spotFailures > s.spotPasses;
  };
  const dropOrphan = (id: string) => {
    const s = sources.find((x) => x.id === id);
    if (s && !s.pinned && !contribs.some((c) => c.sourceId === id)) {
      sources.splice(sources.indexOf(s), 1);
      return 1;
    }
    return 0;
  };
  const removeContrib = (c: Contrib) => {
    contribs.splice(contribs.indexOf(c), 1);
    const s = sources.find((x) => x.id === c.sourceId);
    if (s) refresh(s);
  };

  const deps: Deps = {
    authenticate: (t) => {
      calls.auth++;
      if (t === TOKEN_AUTH_DOWN) return Promise.resolve("unavailable");
      const map: Record<string, { id: string; isAnonymous: boolean }> = {
        [TOKEN]: { id: USER, isAnonymous: false },
        [TOKEN_OTHER]: { id: OTHER, isAnonymous: false },
        [TOKEN_ANON]: { id: ANON, isAnonymous: true }
      };
      return Promise.resolve(map[t] ?? null);
    },

    selectSources: (model, firmware, rawFormatMax) => {
      calls.select.push([model, firmware, rawFormatMax]);
      if (state.throwOn === "select") return Promise.reject(new Error("db down"));
      const servable = sources.filter((s) => s.model === model && s.firmware === firmware && s.rawFormat <= rawFormatMax && isServable(s));
      const out: ListedSourceRow[] = [];
      for (const kind of ["editor-cache", "live-full", "live-readonly"] as const) {
        const rows = servable.filter((s) => s.kind === kind).sort((a, b) =>
          TIER_RANK[a.tier] - TIER_RANK[b.tier] || b.quality - a.quality || b.coverageScore - a.coverageScore ||
          b.contributors - a.contributors || b.networks - a.networks || a.firstSeen - b.firstSeen || (a.id < b.id ? -1 : 1)
        );
        if (!rows.length) continue;
        const r = rows[0];
        out.push({
          id: r.id,
          kind,
          rawFormat: r.rawFormat,
          factHash: r.factHash,
          tier: r.tier,
          quality: r.quality,
          contributors: r.contributors,
          networks: r.networks,
          spotPasses: r.spotPasses,
          spotFailures: r.spotFailures,
          firstSeenDay: day(r.firstSeen)!,
          lastConfirmedDay: day(r.lastConfirmed),
          bytes: r.bytes,
          summary: r.summary,
          alternatives: rows.length
        });
      }
      return Promise.resolve(out);
    },

    // Returns any row by id: the handler must refuse the unservable ones itself.
    getSource: (id) => Promise.resolve(sources.find((s) => s.id === id) ?? null),

    contribute: (a) => {
      calls.contribute.push(a);
      if (state.force) return Promise.resolve(state.force);
      let src = sources.find((s) => s.model === a.model && s.firmware === a.firmware && s.kind === a.kind && s.factHash === a.factHash);
      if (src?.tier === "rejected") return Promise.resolve({ kind: "rejected" });
      if (src && contribs.some((c) => c.sourceId === src!.id && c.userId === a.userId)) {
        return Promise.resolve({ kind: "ok", sourceId: src.id, created: false, deduped: true, confirmed: false, tier: src.tier, contributors: src.contributors, networks: src.networks });
      }
      if (contribs.filter((c) => c.userId === a.userId).length >= a.maxPerWindow) {
        return Promise.resolve({ kind: "limited", reason: "rate", scope: "uploader", retryAfterSeconds: 1234 });
      }
      if (usage.filter((u) => u.key === a.networkKey && u.action === "contribute").length >= a.netMaxPerWindow) {
        return Promise.resolve({ kind: "limited", reason: "rate", scope: "network", retryAfterSeconds: 2345 });
      }
      for (const old of contribs.filter((c) => c.userId === a.userId && c.model === a.model && c.firmware === a.firmware && c.kind === a.kind && c.sourceId !== src?.id)) {
        removeContrib(old);
        dropOrphan(old.sourceId);
      }
      let created = false;
      if (!src) {
        src = {
          id: nextId(),
          model: a.model,
          firmware: a.firmware,
          kind: a.kind,
          rawFormat: a.rawFormat,
          factHash: a.factHash,
          tier: "candidate",
          quality: a.quality,
          summary: a.summary,
          source: a.source,
          pinned: false,
          contributors: 0,
          quarantined: false,
          coverageScore: a.coverageScore,
          networks: 0,
          spotPasses: 0,
          spotFailures: 0,
          bytes: a.bytes,
          firstSeen: NOW,
          lastConfirmed: null
        };
        sources.push(src);
        created = true;
      }
      const first = !contribs.some((c) => c.sourceId === src!.id && c.networkKey === a.networkKey);
      contribs.push({
        id: nextId(),
        sourceId: src.id,
        userId: a.userId,
        networkKey: a.networkKey,
        firstOfNetwork: first,
        model: a.model,
        firmware: a.firmware,
        kind: a.kind,
        createdAt: NOW,
        linkedUntil: NOW + 180 * DAY
      });
      usage.push({ key: a.networkKey, action: "contribute" });
      if (!created) {
        src.lastConfirmed = NOW;
        if (src.kind !== "editor-cache") src.quality = Math.max(src.quality, a.quality);
      }
      refresh(src);
      return Promise.resolve({ kind: "ok", sourceId: src.id, created, deduped: !created, confirmed: !created, tier: src.tier, contributors: src.contributors, networks: src.networks });
    },

    withdraw: (a) => {
      calls.withdraw.push(a);
      const gone = contribs.filter((c) =>
        c.userId === a.userId && (a.sourceId === null || c.sourceId === a.sourceId) && (a.model === null || c.model === a.model) &&
        (a.firmware === null || c.firmware === a.firmware)
      );
      const ids = new Set(gone.map((c) => c.sourceId));
      gone.forEach(removeContrib);
      let deleted = 0;
      for (const id of ids) deleted += dropOrphan(id);
      return Promise.resolve({ withdrawn: gone.length, deletedSources: deleted });
    },

    listMine: (userId, limit) => {
      calls.mine.push([userId, limit]);
      return Promise.resolve(
        contribs.filter((c) => c.userId === userId).slice(0, limit).map((c): ContributionSummary => ({
          id: c.id,
          sourceId: c.sourceId,
          model: c.model,
          firmware: c.firmware,
          kind: c.kind,
          factHash: sources.find((s) => s.id === c.sourceId)?.factHash ?? null,
          createdAt: new Date(c.createdAt).toISOString(),
          linkedUntil: new Date(c.linkedUntil).toISOString()
        }))
      );
    },

    report: (a) => {
      calls.report.push(a);
      if (state.forceReport) return Promise.resolve(state.forceReport);
      const s = sources.find((x) => x.id === a.sourceId);
      if (!s) return Promise.resolve({ kind: "not-found" });
      if (usage.filter((u) => u.key === a.networkKey && u.action === "report").length >= a.netMaxPerWindow) {
        return Promise.resolve({ kind: "limited", reason: "rate", scope: "network", retryAfterSeconds: 99 });
      }
      const prior = reports.find((r) => r.sourceId === a.sourceId && r.userId === a.userId);
      if (prior) Object.assign(prior, { verdict: a.verdict, networkKey: a.networkKey });
      else reports.push({ sourceId: a.sourceId, userId: a.userId, networkKey: a.networkKey, verdict: a.verdict });
      usage.push({ key: a.networkKey, action: "report" });
      const counted = (v: string) =>
        new Set(reports.filter((r) =>
          r.sourceId === s.id && r.verdict === v &&
          !contribs.some((c) => c.sourceId === s.id && (c.userId === r.userId || c.networkKey === r.networkKey))
        ).map((r) => r.networkKey)).size;
      s.spotPasses = Math.max(s.spotPasses, counted("passed"));
      s.spotFailures = Math.max(s.spotFailures, counted("failed"));
      refresh(s);
      return Promise.resolve({ kind: "ok", quarantined: s.quarantined });
    }
  };
  return { deps, sources, contribs, reports, usage, calls, state };
}

/** A source row put directly (as the maintainer or another path would). */
function putSource(f: ReturnType<typeof makeDeps>, patch: Partial<Src> = {}): Src {
  const s: Src = {
    id: `00000000-0000-4000-9000-${String(f.sources.length + 1).padStart(12, "0")}`,
    model: 17,
    firmware: "13.0",
    kind: "editor-cache",
    rawFormat: 1,
    factHash: "f".repeat(64),
    tier: "candidate",
    quality: 3,
    summary: { records: 2500 },
    source: { kind: "editor-cache", firmware: "13.0", records: [] },
    pinned: false,
    contributors: 1,
    quarantined: false,
    coverageScore: 2500,
    networks: 1,
    spotPasses: 0,
    spotFailures: 0,
    bytes: 400_000,
    firstSeen: NOW - 10 * DAY,
    lastConfirmed: null,
    ...patch
  };
  f.sources.push(s);
  return s;
}

// ── requests ──

function req(method: string, path: string, opts: { token?: string; body?: unknown; raw?: BodyInit; ip?: string; headers?: Record<string, string> } = {}): Request {
  const headers: Record<string, string> = { "cf-connecting-ip": opts.ip ?? IP, ...(opts.headers ?? {}) };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  let body: BodyInit | undefined = opts.raw;
  if (opts.body !== undefined) {
    body = JSON.stringify(opts.body);
    headers["content-type"] = "application/json";
  }
  return new Request(`${BASE}${path}`, { method, headers, body });
}
const share = (source: Json, opts: { token?: string; ip?: string; overrides?: Record<string, unknown> } = {}) =>
  req("POST", "", { token: opts.token ?? TOKEN, ip: opts.ip, body: envelope(source, opts.overrides) });

async function call(f: ReturnType<typeof makeDeps>, r: Request, cfg: HandlerConfig = SMALL): Promise<{ status: number; body: Json; headers: Headers }> {
  const res = await handleRequest(r, f.deps, cfg);
  const text = await res.text();
  let body: Json = text;
  try {
    body = JSON.parse(text);
  } catch { /* "ok" for OPTIONS */ }
  return { status: res.status, body, headers: res.headers };
}

// ── CORS / routing ──

Deno.test("OPTIONS answers CORS for GET and POST, Retry-After exposed", async () => {
  const f = makeDeps();
  const r = await call(f, req("OPTIONS", ""));
  assertEquals(r.status, 200);
  assertEquals(r.headers.get("access-control-allow-origin"), "*");
  assertEquals(r.headers.get("access-control-allow-methods"), "GET, POST, OPTIONS");
  assertEquals(r.headers.get("access-control-expose-headers"), "Retry-After");
  assertEquals(f.calls.auth, 0);
});

Deno.test("routing: unknown paths 404, wrong methods 405, ?action works", async () => {
  const f = makeDeps();
  assertEquals((await call(f, req("GET", "/nope"))).status, 404);
  assertEquals((await call(f, req("GET", "/source/a/b"))).status, 404);
  assertEquals((await call(f, req("PUT", ""))).status, 405);
  assertEquals((await call(f, req("GET", "/withdraw"))).status, 405);
  assertEquals((await call(f, req("POST", "/mine", { token: TOKEN, body: {} }))).status, 405);
  assertEquals((await call(f, req("POST", "/source/00000000-0000-4000-8000-000000000001", { token: TOKEN, body: {} }))).status, 405);
  const mine = await call(f, req("GET", "?action=mine", { token: TOKEN }));
  assertEquals(mine.status, 200);
  assertEquals(mine.body, { contributions: [] });
  // the platform path prefix is tolerated
  const viaPrefix = await handleRequest(new Request("http://localhost/functions/v1/definition-sources/mine", { headers: { authorization: `Bearer ${TOKEN}` } }), f.deps, SMALL);
  assertEquals(viaPrefix.status, 200);
});

// ── GET: listing ──

Deno.test("GET listing: best row per kind, public cache, alternatives per kind, day dates", async () => {
  const f = makeDeps();
  const best = putSource(f, { factHash: "a".repeat(64), firstSeen: Date.parse("2026-11-20T15:00:00Z"), lastConfirmed: Date.parse("2026-11-28T09:00:00Z"), contributors: 2, networks: 2, tier: "verified", spotPasses: 4, spotFailures: 1 });
  putSource(f, { factHash: "b".repeat(64) });
  putSource(f, { factHash: "c".repeat(64), kind: "live-readonly", quality: 2, coverageScore: 60_000 });
  putSource(f, { factHash: "d".repeat(64), tier: "rejected", pinned: true, quality: 3, coverageScore: 99_999 });
  const r = await call(f, req("GET", "?model=17&firmware=13.0&rawFormat=1"));
  assertEquals(r.status, 200);
  assertEquals(r.headers.get("cache-control"), "public, max-age=300");
  assertEquals(r.body.model, 17);
  assertEquals(r.body.firmware, "13.0");
  assertEquals(r.body.alternatives, { "editor-cache": 2, "live-readonly": 1, "live-full": 0 });
  assertEquals(r.body.sources.map((s: Json) => s.kind), ["editor-cache", "live-readonly"]);
  assertEquals(r.body.sources[0], {
    id: best.id,
    kind: "editor-cache",
    rawFormat: 1,
    factHash: "a".repeat(64),
    tier: "verified",
    quality: 3,
    contributors: 2,
    networks: 2,
    spotChecks: { passed: 4, failed: 1 },
    firstSeen: "2026-11-20",
    lastConfirmedAt: "2026-11-28",
    bytes: 400_000,
    summary: { records: 2500 }
  });
  assertEquals(f.calls.select, [[17, "13.0", 1]]);
});

Deno.test("GET listing: none -> sources [] (no 404); rawFormat defaults to 1; a model that does not contribute skips the DB", async () => {
  const f = makeDeps();
  const r = await call(f, req("GET", "?model=17&firmware=14.0"));
  assertEquals(r.status, 200);
  assertEquals(r.body, { model: 17, firmware: "14.0", sources: [], alternatives: { "editor-cache": 0, "live-readonly": 0, "live-full": 0 }, allowAnonymous: true });
  assertEquals(f.calls.select, [[17, "14.0", 1]]);
  const am4 = await call(f, req("GET", "?model=21&firmware=1.0"));
  assertEquals(am4.status, 200);
  assertEquals(am4.body.sources, []);
  assertEquals(f.calls.select.length, 1);
  assertEquals((await call(f, req("GET", "?model=17&firmware=13.00"))).body.firmware, "13.0");
});

Deno.test("GET listing: advertises allowAnonymous (the switch POST enforces), additive and last; per-source and /mine bodies carry no such field", async () => {
  const f = makeDeps();
  const s = putSource(f, { factHash: "a".repeat(64) });
  const on = await call(f, req("GET", "?model=17&firmware=13.0&rawFormat=1"), { ...SMALL, allowAnonymous: true });
  const off = await call(f, req("GET", "?model=17&firmware=13.0&rawFormat=1"), { ...SMALL, allowAnonymous: false });
  assertEquals([on.status, off.status], [200, 200]);
  assertEquals(on.body.allowAnonymous, true);
  assertEquals(off.body.allowAnonymous, false);
  // a real boolean, appended after the existing fields (which keep their names and order)
  assertEquals(Object.keys(on.body), ["model", "firmware", "sources", "alternatives", "allowAnonymous"]);
  assertEquals(Object.keys(off.body), ["model", "firmware", "sources", "alternatives", "allowAnonymous"]);
  // nothing else of the listing moves with the switch, and the cache policy is unchanged
  assertEquals({ ...off.body, allowAnonymous: true }, on.body);
  assertEquals(on.headers.get("cache-control"), "public, max-age=300");
  assertEquals(off.headers.get("cache-control"), "public, max-age=300");
  // also when nothing is listed (a model that does not contribute skips the DB but still reports the switch)
  const none = await call(f, req("GET", "?model=21&firmware=1.0"), { ...SMALL, allowAnonymous: false });
  assertEquals(none.body.allowAnonymous, false);
  // the advertised value is the one POST enforces
  const refused = await call(f, share(editorCacheFixture(), { token: TOKEN_ANON }), { ...SMALL, allowAnonymous: false });
  assertEquals([refused.status, refused.body.error], [403, "account-required"]);
  const accepted = await call(f, share(editorCacheFixture(), { token: TOKEN_ANON }), { ...SMALL, allowAnonymous: true });
  assertEquals(accepted.status, 201);
  // per-source bodies and /mine are untouched
  const one = await call(f, req("GET", `/source/${s.id}`), { ...SMALL, allowAnonymous: false });
  assertEquals("allowAnonymous" in one.body, false);
  const mine = await call(f, req("GET", "/mine", { token: TOKEN }), { ...SMALL, allowAnonymous: false });
  assertEquals("allowAnonymous" in mine.body, false);
});

Deno.test("GET listing: bad query -> 400 invalid-request (not cached)", async () => {
  const f = makeDeps();
  for (const q of ["", "?model=17", "?model=x&firmware=13.0", "?model=17&firmware=13.0&rawFormat=0"]) {
    const r = await call(f, req("GET", q));
    assertEquals([r.status, r.body.error], [400, "invalid-request"], q);
    assertEquals(r.headers.get("cache-control"), null);
  }
});

// ── GET /source/<id> ──

Deno.test("GET /source/<id>: the sanitized body with the public fields only, cached a day", async () => {
  const f = makeDeps();
  const s = putSource(f, { source: { kind: "editor-cache", records: [1] } });
  const r = await call(f, req("GET", `/source/${s.id.toUpperCase()}`));
  assertEquals(r.status, 200);
  assertEquals(r.headers.get("cache-control"), "public, max-age=86400");
  assertEquals(r.body, {
    id: s.id,
    model: 17,
    firmware: "13.0",
    kind: "editor-cache",
    rawFormat: 1,
    factHash: "f".repeat(64),
    tier: "candidate",
    quality: 3,
    summary: { records: 2500 },
    source: { kind: "editor-cache", records: [1] }
  });
});

Deno.test("GET /source/<id>: 404 for missing, rejected, quarantined and orphaned rows; pinned official without votes is served", async () => {
  const f = makeDeps();
  const rejected = putSource(f, { tier: "rejected", pinned: true });
  const quarantined = putSource(f, { quarantined: true, spotFailures: 3 });
  const orphan = putSource(f, { contributors: 0 });
  const official = putSource(f, { tier: "official", pinned: true, contributors: 0 });
  for (const id of [rejected.id, quarantined.id, orphan.id, "00000000-0000-4000-8000-00000000abcd"]) {
    const r = await call(f, req("GET", `/source/${id}`));
    assertEquals([r.status, r.body], [404, { error: "not-found" }], id);
  }
  assertEquals((await call(f, req("GET", `/source/${official.id}`))).status, 200);
  assertEquals((await call(f, req("GET", "/source/not-a-uuid"))).status, 400);
});

// ── POST: contribute ──

Deno.test("contribute: 201 created with server-computed facts; the stored source is the sanitized copy", async () => {
  const f = makeDeps();
  const src = editorCacheFixture();
  Object.assign(src, { id: "editor-cache@x#1", origin: "local", contentSha256: "ab".repeat(32), capturedAt: "2026-11-22T17:03:00Z", unknown: 1 });
  const r = await call(f, share(src));
  assertEquals(r.status, 201, JSON.stringify(r.body));
  const golden = GOLDENS.sources[0].factHash;
  assertEquals(r.body, { sourceId: f.sources[0].id, factHash: golden, created: true, deduped: false, confirmed: false, tier: "candidate", contributors: 1, networks: 1 });
  const a = f.calls.contribute[0];
  assertEquals(a.userId, USER);
  assertEquals(a.factHash, golden);
  assertEquals(a.quality, 3);
  assertEquals(a.coverageScore, 225);
  assertEquals(a.summary.records, 225);
  assertEquals(a.kind, "editor-cache");
  assertEquals(a.rawFormat, 1);
  assertEquals(a.consentVersion, 1);
  // what is stored: no contentSha256 value, no id/origin/unknown keys, the day only
  assertEquals(a.source.contentSha256, null);
  assertFalse("id" in a.source || "origin" in a.source || "unknown" in a.source);
  assertEquals(a.source.capturedAt, "2026-11-22T00:00:00.000Z");
  assertEquals(a.bytes, new TextEncoder().encode(JSON.stringify(a.source)).length);
  // the limits passed into SQL are the contract's
  assertEquals([a.maxPerWindow, a.windowSeconds, a.netMaxPerWindow, a.quotaBytes, a.quotaWindowSeconds, a.netQuotaBytes], [10, 3600, 10, 41943040, 2592000, 41943040]);
});

Deno.test("contribute: the network reaches SQL only as a 64-hex key of this store's own domain", async () => {
  const f = makeDeps();
  ipDiagnostics.logged = false;
  logged.length = 0;
  await call(f, share(editorCacheFixture()));
  const key = f.calls.contribute[0].networkKey;
  assertMatch(key, /^[0-9a-f]{64}$/);
  assertEquals(key, await networkKey(SALT, `v4:${IP}`, NETWORK_DOMAIN));
  // the same network and salt never give the editor-cache store's key
  assertNotEquals(key, await editorCacheNetworkKey(SALT, `v4:${IP}`));
  assertFalse(JSON.stringify(f.calls.contribute[0]).includes(IP));
  // the header diagnostic logs names only
  assert(logged.some(([, m]) => m.includes("cf-connecting-ip")));
  assertFalse(logged.some(([, m]) => m.includes(IP)));
});

Deno.test("contribute: dedupe and confirmation — same uploader deduped, another uploader confirms, verified at 2 x 2", async () => {
  const f = makeDeps();
  const first = await call(f, share(editorCacheFixture()));
  assertEquals(first.status, 201);
  const again = await call(f, share(editorCacheFixture()));
  assertEquals(again.status, 200);
  assertEquals(again.body, { ...first.body, created: false, deduped: true, confirmed: false });
  // another uploader on the same network: confirms, but one network is not enough for verified
  const anon = await call(f, share(editorCacheFixture(), { token: TOKEN_ANON }));
  assertEquals([anon.status, anon.body.confirmed, anon.body.tier, anon.body.contributors, anon.body.networks], [200, true, "candidate", 2, 1]);
  // a third on another network: verified
  const other = await call(f, share(editorCacheFixture(), { token: TOKEN_OTHER, ip: IP2 }));
  assertEquals([other.status, other.body.deduped, other.body.confirmed, other.body.tier, other.body.contributors, other.body.networks], [200, true, true, "verified", 3, 2]);
  assertEquals(f.sources.length, 1);
});

Deno.test("contribute: different facts make another row; a re-share of the same kind moves the uploader's vote", async () => {
  const f = makeDeps();
  await call(f, share(editorCacheFixture()));
  const changed = editorCacheFixture();
  changed.records[0].max = 21;
  const r = await call(f, share(changed));
  assertEquals(r.status, 201);
  assertNotEquals(r.body.factHash, GOLDENS.sources[0].factHash);
  assertEquals(f.sources.length, 1, "the orphaned first row was deleted with the moved vote");
  assertEquals(f.contribs.length, 1);
});

Deno.test("contribute: live sources and the plausibility floor (production config)", async () => {
  const f = makeDeps();
  const small = await call(f, share(liveFixture()), CFG);
  assertEquals([small.status, small.body.error], [422, "implausible"]);
  const live = await call(f, share(bigLive()), CFG);
  assertEquals(live.status, 201, JSON.stringify(live.body));
  assertEquals(f.calls.contribute[0].quality, 3);
  assertEquals(f.calls.contribute[0].coverageScore, 20 * 1000 + (f.calls.contribute[0].summary.records as number));
  const ec = await call(f, share(bigEditorCache()), CFG);
  assertEquals(ec.status, 201, JSON.stringify(ec.body));
  assertEquals(f.calls.contribute[1].factHash, await sourceFactHash(f.calls.contribute[1].source, { model: 17, firmware: "12.0" }));
});

Deno.test("contribute: validation answers pass through (400 / 409 / 422) and nothing reaches SQL", async () => {
  const f = makeDeps();
  const cases: Array<[Json, number, string]> = [
    [envelope(editorCacheFixture(), { firmware: "12.00" }), 400, "invalid-request"],
    [envelope(editorCacheFixture(), { consentAt: undefined }), 400, "consent-required"],
    [envelope(editorCacheFixture(), { model: 0x14 }), 409, "unsupported-model"],
    [envelope(editorCacheFixture(), { rawFormat: 2 }), 422, "unsupported-raw-format"],
    [envelope({ ...editorCacheFixture(), issues: [] }), 422, "tolerant-source"],
    [envelope({ ...editorCacheFixture(), fileVersion: "13.0" }), 422, "version-mismatch"],
    [envelope(editorCacheFixture(), { firmware: "13.0" }), 422, "firmware-inconsistent"]
  ];
  const userData = editorCacheFixture();
  userData.records[0].id = 0xffff;
  cases.push([envelope(userData), 422, "contains-user-data"]);
  for (const [body, status, error] of cases) {
    const r = await call(f, req("POST", "", { token: TOKEN, body }));
    assertEquals([r.status, r.body.error], [status, error], error);
  }
  const bad = editorCacheFixture();
  bad.records[3].min = "x";
  const r = await call(f, req("POST", "", { token: TOKEN, body: envelope(bad) }));
  assertEquals(r.body, { error: "invalid-source", path: "source.records[3].min", reason: "expected a finite number" });
  assertEquals(f.calls.contribute.length, 0);
});

Deno.test("contribute: body problems -> 400 empty-body / invalid-json", async () => {
  const f = makeDeps();
  assertEquals((await call(f, req("POST", "", { token: TOKEN, raw: "" }))).body.error, "empty-body");
  assertEquals((await call(f, req("POST", "", { token: TOKEN, raw: "{nope" }))).body.error, "invalid-json");
  assertEquals((await call(f, req("POST", "", { token: TOKEN, raw: new Uint8Array([0x7b, 0xff, 0x7d]) }))).body.error, "invalid-json");
});

Deno.test("413 too-large: declared or streamed beyond 2 MiB, and a withdraw body beyond 8 KiB", async () => {
  const f = makeDeps();
  const declared = await call(f, req("POST", "", { token: TOKEN, raw: "{}", headers: { "content-length": String(MAX_CONTRIBUTION_BYTES + 1) } }));
  assertEquals(declared.status, 413);
  assertEquals(declared.body, { error: "too-large", limit: MAX_CONTRIBUTION_BYTES, bytes: MAX_CONTRIBUTION_BYTES + 1 });
  // a chunked body without Content-Length is cut off at the cap, never buffered whole
  const chunk = new Uint8Array(512 * 1024).fill(0x20);
  let sent = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      if (sent >= 8) return c.close();
      sent++;
      c.enqueue(chunk);
    }
  });
  const streamed = await call(f, new Request(BASE, { method: "POST", headers: { authorization: `Bearer ${TOKEN}` }, body: stream }));
  assertEquals(streamed.status, 413);
  assert(streamed.body.bytes > MAX_CONTRIBUTION_BYTES);
  assert(sent < 8, "the reader stopped early");
  const w = await call(f, req("POST", "/withdraw", { token: TOKEN, body: { all: true, pad: "x".repeat(9000) } }));
  assertEquals([w.status, w.body.limit], [413, 8192]);
  assertEquals(f.calls.contribute.length + f.calls.withdraw.length, 0);
});

Deno.test("413 too-large: a sanitized source above the cap (number spellings grow) is refused before SQL", async () => {
  const f = makeDeps();
  // The request text uses short spellings (4e9); the stored JSON writes them out (4000000000), so it is longer.
  const text = JSON.stringify(envelope(editorCacheFixture())).replace(/"t([12])":\d+/g, '"t$1":4e9');
  const stored = new TextEncoder().encode(JSON.stringify(JSON.parse(text).source)).length;
  assert(stored > text.length + 100, `${stored} vs ${text.length}`);
  const cfg: HandlerConfig = { ...SMALL, maxContributionBytes: text.length + 50 };
  const r = await call(f, req("POST", "", { token: TOKEN, raw: text }), cfg);
  assertEquals(r.status, 413, JSON.stringify(r.body));
  assertEquals(r.body, { error: "too-large", limit: text.length + 50, bytes: stored });
  assertEquals(f.calls.contribute.length, 0);
});

// ── auth matrix ──

Deno.test("auth: 401 without, with a malformed and with an unknown token (malformed: no Auth round trip)", async () => {
  const f = makeDeps();
  for (const r of [
    req("POST", "", { body: envelope(editorCacheFixture()) }),
    req("POST", "", { body: envelope(editorCacheFixture()), headers: { authorization: "Bearer not-a-jwt" } }),
    req("POST", "", { body: envelope(editorCacheFixture()), headers: { authorization: "Basic abc" } })
  ]) {
    const res = await call(f, r);
    assertEquals([res.status, res.body], [401, { error: "unauthorized" }]);
  }
  assertEquals(f.calls.auth, 0);
  const unknown = await call(f, share(editorCacheFixture(), { token: TOKEN_UNKNOWN }));
  assertEquals(unknown.status, 401);
  for (const path of ["/withdraw", "/report"]) assertEquals((await call(f, req("POST", path, { body: { all: true } }))).status, 401);
  assertEquals((await call(f, req("GET", "/mine"))).status, 401);
  assertEquals(f.calls.contribute.length, 0);
});

Deno.test("auth: anonymous sessions share when allowed; 403 account-required for contribute/report when not; withdraw and /mine stay open", async () => {
  const f = makeDeps();
  const ok = await call(f, share(editorCacheFixture(), { token: TOKEN_ANON }));
  assertEquals(ok.status, 201);
  const off: HandlerConfig = { ...SMALL, allowAnonymous: false };
  const refused = await call(f, share(liveFixture(), { token: TOKEN_ANON }), off);
  assertEquals([refused.status, refused.body.error], [403, "account-required"]);
  const report = await call(f, req("POST", "/report", { token: TOKEN_ANON, body: { sourceId: ok.body.sourceId, verdict: "passed", checked: 24, answered: 24, mismatches: 0 } }), off);
  assertEquals([report.status, report.body.error], [403, "account-required"]);
  // an account is unaffected
  assertEquals((await call(f, share(liveFixture()), off)).status, 201);
  // the anonymous uploader can still see and withdraw what it shared
  const mine = await call(f, req("GET", "/mine", { token: TOKEN_ANON }), off);
  assertEquals(mine.body.contributions.length, 1);
  const w = await call(f, req("POST", "/withdraw", { token: TOKEN_ANON, body: { sourceId: ok.body.sourceId } }), off);
  assertEquals([w.status, w.body], [200, { withdrawn: 1, deletedSources: 1 }]);
});

// ── 429 / 409 rejected mapping ──

Deno.test("429: rate-limited / quota-exceeded with scope uploader | network, Retry-After header", async () => {
  const f = makeDeps();
  const cases: Array<[ContributeResult, string, string, Record<string, number>]> = [
    [{ kind: "limited", reason: "rate", scope: "uploader", retryAfterSeconds: 120.2 }, "rate-limited", "uploader", { limit: 10, windowSeconds: 3600, retryAfterSeconds: 121 }],
    [{ kind: "limited", reason: "rate", scope: "network", retryAfterSeconds: 30 }, "rate-limited", "network", { limit: 10, windowSeconds: 3600, retryAfterSeconds: 30 }],
    [{ kind: "limited", reason: "quota", scope: "uploader", retryAfterSeconds: 86400 }, "quota-exceeded", "uploader", { quotaBytes: 41943040, windowSeconds: 2592000, retryAfterSeconds: 86400 }],
    [{ kind: "limited", reason: "quota", scope: "network", retryAfterSeconds: 0 }, "quota-exceeded", "network", { quotaBytes: 41943040, windowSeconds: 2592000, retryAfterSeconds: 1 }]
  ];
  for (const [force, error, scope, extra] of cases) {
    f.state.force = force;
    const r = await call(f, share(editorCacheFixture()));
    assertEquals(r.status, 429);
    assertEquals(r.body, { error, scope, ...extra });
    assertEquals(r.headers.get("retry-after"), String(extra.retryAfterSeconds));
  }
});

Deno.test("429 from the fake's own limits: 11th contribution of an uploader in the window", async () => {
  const f = makeDeps();
  for (let i = 0; i < 10; i++) {
    const s = editorCacheFixture();
    s.records[0].max = 100 + i;
    // different firmwares so no vote is moved
    s.firmware = `12.${i}`;
    const r = await call(f, share(s, { ip: `192.0.2.${i}` }));
    assertEquals(r.status, 201, JSON.stringify(r.body));
  }
  const s = editorCacheFixture();
  s.firmware = "12.99";
  const r = await call(f, share(s, { ip: "192.0.2.200" }));
  assertEquals([r.status, r.body.error, r.body.scope], [429, "rate-limited", "uploader"]);
});

Deno.test("409 rejected: facts the maintainer rejected are refused", async () => {
  const f = makeDeps();
  const hash = GOLDENS.sources[0].factHash;
  putSource(f, { firmware: "12.0", factHash: hash, tier: "rejected", pinned: true });
  const r = await call(f, share(editorCacheFixture()));
  assertEquals([r.status, r.body.error, r.body.factHash], [409, "rejected", hash]);
});

Deno.test("SQLSTATE mapping: XQ001/XQ002 uploader, XQ005/XQ006 network, XQ007 rejected, others rethrown", () => {
  assertEquals(contributeOutcomeFromSqlError({ code: "XQ001", details: "120" }), { kind: "limited", reason: "rate", scope: "uploader", retryAfterSeconds: 120 });
  assertEquals(contributeOutcomeFromSqlError({ code: "XQ002", details: "86400" }), { kind: "limited", reason: "quota", scope: "uploader", retryAfterSeconds: 86400 });
  assertEquals(contributeOutcomeFromSqlError({ code: "XQ005", details: "7" }), { kind: "limited", reason: "rate", scope: "network", retryAfterSeconds: 7 });
  assertEquals(contributeOutcomeFromSqlError({ code: "XQ006", details: null }), { kind: "limited", reason: "quota", scope: "network", retryAfterSeconds: 60 });
  assertEquals(contributeOutcomeFromSqlError({ code: "XQ007" }), { kind: "rejected" });
  assertEquals(contributeOutcomeFromSqlError({ code: "22023" }), null);
  assertEquals(contributeOutcomeFromSqlError({ code: "XQ003" }), null);
  assertEquals(reportOutcomeFromSqlError({ code: "XQ001", details: "5" }), { kind: "limited", reason: "rate", scope: "uploader", retryAfterSeconds: 5 });
  assertEquals(reportOutcomeFromSqlError({ code: "XQ005", details: "garbage" }), { kind: "limited", reason: "rate", scope: "network", retryAfterSeconds: 60 });
  assertEquals(reportOutcomeFromSqlError({ code: "XQ002" }), null);
});

// ── paused: kill switch and the network-key secret ──

Deno.test("salt missing or short -> contribute/report 503 paused; GET, withdraw and /mine keep working", async () => {
  for (const ipSalt of [null, "too-short"]) {
    const f = makeDeps();
    const s = putSource(f);
    const cfg: HandlerConfig = { ...SMALL, ipSalt };
    const c = await call(f, share(editorCacheFixture()), cfg);
    assertEquals([c.status, c.body.error], [503, "paused"]);
    const rep = await call(f, req("POST", "/report", { token: TOKEN, body: { sourceId: s.id, verdict: "passed", checked: 24, answered: 24, mismatches: 0 } }), cfg);
    assertEquals([rep.status, rep.body.error], [503, "paused"]);
    assertEquals(f.calls.auth, 0, "paused before authenticating");
    assertEquals((await call(f, req("GET", "?model=17&firmware=13.0"), cfg)).status, 200);
    assertEquals((await call(f, req("GET", `/source/${s.id}`), cfg)).status, 200);
    assertEquals((await call(f, req("GET", "/mine", { token: TOKEN }), cfg)).status, 200);
    assertEquals((await call(f, req("POST", "/withdraw", { token: TOKEN, body: { all: true } }), cfg)).status, 200);
  }
});

Deno.test("DEFINITION_SOURCES=readonly pauses writes only; =off pauses public reads too; withdraw and /mine always work", async () => {
  const f = makeDeps();
  const s = putSource(f);
  const ro: HandlerConfig = { ...SMALL, mode: "readonly" };
  assertEquals((await call(f, share(editorCacheFixture()), ro)).status, 503);
  assertEquals((await call(f, req("GET", "?model=17&firmware=13.0"), ro)).status, 200);
  assertEquals((await call(f, req("GET", `/source/${s.id}`), ro)).status, 200);
  const off: HandlerConfig = { ...SMALL, mode: "off" };
  for (const r of [share(editorCacheFixture()), req("GET", "?model=17&firmware=13.0"), req("GET", `/source/${s.id}`)]) {
    const res = await call(f, r, off);
    assertEquals([res.status, res.body.error], [503, "paused"]);
  }
  assertEquals((await call(f, req("GET", "/mine", { token: TOKEN }), off)).status, 200);
  assertEquals((await call(f, req("POST", "/withdraw", { token: TOKEN, body: { all: true } }), off)).status, 200);
});

// ── withdraw ──

Deno.test("withdraw one: own -> counts; foreign or unknown -> 404; the orphan is deleted, a confirmed row stays", async () => {
  const f = makeDeps();
  const mine = (await call(f, share(editorCacheFixture()))).body.sourceId;
  const foreign = putSource(f);
  const nf = await call(f, req("POST", "/withdraw", { token: TOKEN, body: { sourceId: foreign.id } }));
  assertEquals([nf.status, nf.body], [404, { error: "not-found" }]);
  assertEquals((await call(f, req("POST", "/withdraw", { token: TOKEN, body: { sourceId: "00000000-0000-4000-8000-00000000ffff" } }))).status, 404);
  // another uploader confirmed it: withdrawing one vote keeps the row
  await call(f, share(editorCacheFixture(), { token: TOKEN_OTHER, ip: IP2 }));
  const w = await call(f, req("POST", "/withdraw", { token: TOKEN, body: { sourceId: mine } }));
  assertEquals([w.status, w.body], [200, { withdrawn: 1, deletedSources: 0 }]);
  assertEquals(f.sources.find((s) => s.id === mine)?.contributors, 1);
  const last = await call(f, req("POST", "/withdraw", { token: TOKEN_OTHER, body: { sourceId: mine } }));
  assertEquals(last.body, { withdrawn: 1, deletedSources: 1 });
  assertFalse(f.sources.some((s) => s.id === mine));
  assertEquals(f.calls.withdraw[0], { userId: USER, sourceId: foreign.id, model: null, firmware: null });
});

Deno.test("withdraw all (optionally for one model / firmware); 0 withdrawn is not an error; bad bodies 400", async () => {
  const f = makeDeps();
  await call(f, share(editorCacheFixture()));
  await call(f, share(liveFixture()));
  const scoped = await call(f, req("POST", "/withdraw", { token: TOKEN, body: { all: true, model: 17, firmware: "13.0" } }));
  assertEquals(scoped.body, { withdrawn: 0, deletedSources: 0 });
  assertEquals(f.calls.withdraw[0], { userId: USER, sourceId: null, model: 17, firmware: "13.0" });
  const all = await call(f, req("POST", "/withdraw", { token: TOKEN, body: { all: true } }));
  assertEquals(all.body, { withdrawn: 2, deletedSources: 2 });
  for (const body of [{}, { all: false }, { sourceId: "x" }, { sourceId: f.contribs[0]?.id ?? "00000000-0000-4000-8000-000000000001", all: true }]) {
    assertEquals((await call(f, req("POST", "/withdraw", { token: TOKEN, body }))).status, 400, JSON.stringify(body));
  }
});

// ── /mine ──

Deno.test("GET /mine: the caller's own linked contributions only, private, limit 100", async () => {
  const f = makeDeps();
  const a = (await call(f, share(editorCacheFixture()))).body;
  await call(f, share(liveFixture(), { token: TOKEN_OTHER }));
  const r = await call(f, req("GET", "/mine", { token: TOKEN }));
  assertEquals(r.status, 200);
  assertEquals(r.headers.get("cache-control"), "private, no-store");
  assertEquals(r.body.contributions.length, 1);
  const c = r.body.contributions[0];
  assertEquals([c.sourceId, c.model, c.firmware, c.kind, c.factHash], [a.sourceId, 17, "12.0", "editor-cache", a.factHash]);
  assertEquals(c.linkedUntil, new Date(NOW + 180 * DAY).toISOString());
  assertEquals(f.calls.mine.at(-1), [USER, 100]);
});

// ── report ──

const reportBody = (sourceId: string, verdict: "passed" | "failed" = "failed") =>
  ({ sourceId, verdict, checked: 24, answered: 24, mismatches: verdict === "failed" ? 2 : 0, app: { forgefx: "0.11.0", host: "pc" } });

Deno.test("report: ok -> { ok, quarantined }; 3 failing networks quarantine a candidate, which is then hidden", async () => {
  const f = makeDeps();
  const s = putSource(f, { firmware: "12.0" });
  const users = [TOKEN, TOKEN_OTHER, TOKEN_ANON];
  const ips = ["192.0.2.1", "192.0.2.2", "192.0.2.3"];
  let last: Json;
  for (let i = 0; i < 3; i++) last = await call(f, req("POST", "/report", { token: users[i], ip: ips[i], body: reportBody(s.id) }));
  assertEquals([last.status, last.body], [200, { ok: true, quarantined: true }]);
  assertEquals(f.calls.report[0].app, { forgefx: "0.11.0" });
  assertEquals([f.calls.report[0].maxPerWindow, f.calls.report[0].netMaxPerWindow, f.calls.report[0].windowSeconds], [30, 30, 3600]);
  assertEquals((await call(f, req("GET", `/source/${s.id}`))).status, 404);
  assertEquals((await call(f, req("GET", "?model=17&firmware=12.0"))).body.sources, []);
});

Deno.test("report: unknown source 404; invalid body 400; limits 429 with scope", async () => {
  const f = makeDeps();
  const nf = await call(f, req("POST", "/report", { token: TOKEN, body: reportBody("00000000-0000-4000-8000-00000000eeee") }));
  assertEquals([nf.status, nf.body.error], [404, "not-found"]);
  const s = putSource(f);
  for (const body of [{ ...reportBody(s.id), verdict: "inconclusive" }, { ...reportBody(s.id), mismatches: 0 }, { ...reportBody(s.id), checked: 99 }]) {
    assertEquals((await call(f, req("POST", "/report", { token: TOKEN, body }))).status, 400);
  }
  f.state.forceReport = { kind: "limited", reason: "rate", scope: "uploader", retryAfterSeconds: 42 };
  const lim = await call(f, req("POST", "/report", { token: TOKEN, body: reportBody(s.id) }));
  assertEquals(lim.status, 429);
  assertEquals(lim.body, { error: "rate-limited", scope: "uploader", limit: 30, windowSeconds: 3600, retryAfterSeconds: 42 });
  assertEquals(lim.headers.get("retry-after"), "42");
  f.state.forceReport = { kind: "limited", reason: "rate", scope: "network", retryAfterSeconds: 5 };
  assertEquals((await call(f, req("POST", "/report", { token: TOKEN, body: reportBody(s.id) }))).body.scope, "network");
});

// ── failures ──

Deno.test("a database failure is 500 internal without details", async () => {
  const f = makeDeps();
  f.state.throwOn = "select";
  const r = await call(f, req("GET", "?model=17&firmware=13.0"));
  assertEquals(r.status, 500);
  assertEquals(r.body, { error: "internal", message: "request failed; please try again later" });
});

Deno.test("full flow: share, list, fetch, mine, withdraw", async () => {
  const f = makeDeps();
  const shared = await call(f, share(editorCacheFixture()));
  const list = await call(f, req("GET", "?model=17&firmware=12.0"));
  assertEquals(list.body.sources.length, 1);
  assertEquals(list.body.sources[0].factHash, GOLDENS.sources[0].factHash);
  assertEquals(list.body.sources[0].firstSeen, day(NOW));
  const body = await call(f, req("GET", `/source/${shared.body.sourceId}`));
  assertEquals(body.status, 200);
  // the served source is the codec-shaped fixture (it was already shareable). The fake keeps key order; the real
  // jsonb column returns its own key order — same content, same fact hash (the hash sorts keys).
  assertEquals(body.body.source, editorCacheFixture());
  assertEquals(body.body.factHash, await sourceFactHash(body.body.source, { model: 17, firmware: "12.0" }));
  assertEquals((await call(f, req("GET", "/mine", { token: TOKEN }))).body.contributions.length, 1);
  assertEquals((await call(f, req("POST", "/withdraw", { token: TOKEN, body: { all: true } }))).body, { withdrawn: 1, deletedSources: 1 });
  assertEquals((await call(f, req("GET", `/source/${shared.body.sourceId}`))).status, 404);
});

// ── Auth outage (review fix) ──

Deno.test("an Auth outage is 503 auth-unavailable with Retry-After, never 401, and nothing reaches SQL", async () => {
  const f = makeDeps();
  const s = putSource(f);
  for (const r of [
    req("POST", "", { token: TOKEN_AUTH_DOWN, body: envelope(editorCacheFixture()) }),
    req("POST", "/withdraw", { token: TOKEN_AUTH_DOWN, body: { all: true } }),
    req("GET", "/mine", { token: TOKEN_AUTH_DOWN }),
    req("POST", "/report", { token: TOKEN_AUTH_DOWN, body: { sourceId: s.id, verdict: "passed", checked: 24, answered: 24, mismatches: 0 } })
  ]) {
    const res = await call(f, r);
    assertEquals(res.status, 503);
    assertEquals(res.body.error, "auth-unavailable");
    assertEquals(res.headers.get("retry-after"), "30");
  }
  assertEquals(f.calls.contribute.length + f.calls.withdraw.length + f.calls.report.length + f.calls.mine.length, 0);
});

Deno.test("isAuthOutage: network, 5xx, 429 and status-less errors are outages; 4xx are verdicts on the token", () => {
  for (const e of [{ name: "AuthRetryableFetchError", status: 0 }, { status: 0 }, { status: 500 }, { status: 503 }, { status: 429 }, { name: "AuthUnknownError" }, {}]) {
    assert(isAuthOutage(e), JSON.stringify(e));
  }
  for (const e of [{ name: "AuthApiError", status: 401 }, { status: 403 }, { status: 404 }, { status: 400 }, null, undefined]) {
    assertFalse(isAuthOutage(e), JSON.stringify(e));
  }
});
