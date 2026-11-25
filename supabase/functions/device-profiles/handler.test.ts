// Unit tests for the v1 device-profiles edge function. Run with:
//   deno test supabase/functions/device-profiles/
// No Supabase stack or network is needed: handler.ts talks to the database only through `Deps`, which these tests
// replace with an in-memory store. What they therefore do NOT cover — and what needs a local stack or a rolled-back
// staging run — is everything behind that seam: the SQL (the generated `row_count`, its backfill, the index; see
// supabase/tests/database/device_profiles_ranking.test.sql) and the PostgREST adapter in index.ts. The fake store
// below applies the handler's ORDER terms with plain ORDER BY semantics, so what is asserted is the ranking the
// handler ASKS for, on realistic candidate sets (a newer, truncated live walk next to an older, complete editor cache).
// Synthetic profiles only.
import { assert, assertEquals, assertFalse, assertNotEquals } from "jsr:@std/assert@1";
import {
  canonicalJson,
  DEFAULT_CONFIG,
  type Deps,
  type HandlerConfig,
  handleRequest,
  type InsertResult,
  LEGACY_SCHEMAS,
  type NewProfile,
  type OrderTerm,
  PROFILE_ORDER,
  type ProfileFilter,
  type ProfileRow,
  RESPONSE_COLUMNS,
  validateProfile
} from "./handler.ts";

const USER = "11111111-1111-4111-8111-111111111111";
const ANON = "33333333-3333-4333-8333-333333333333";
const TOKEN = "Bearer hdr.payload.user";
const TOKEN_ANON = "Bearer hdr.payload.anon";
const NOW = Date.parse("2026-12-01T12:00:00Z");
const HOUR = 3_600_000;
const BASE = "http://localhost/device-profiles";
const CFG: HandlerConfig = { ...DEFAULT_CONFIG, now: () => NOW };

// ── synthetic profiles ──

/** A BuiltCache-shaped doc that passes validateProfile: `families` families with `ids` parameter ranges each. */
function profileDoc(opts: { families?: number; ids?: number; source?: "live" | "bytes"; schema?: number | null; recordCount?: number } = {}) {
  const { families = 2, ids = 3, source = "bytes", schema = null, recordCount = 10 } = opts;
  const ranges: Record<string, Record<string, unknown>> = {};
  for (let f = 0; f < families; f++) {
    const fam: Record<string, unknown> = {};
    for (let i = 0; i < ids; i++) fam[String(i)] = { kind: "float", min: 0, max: 1 };
    ranges[`f${f}`] = fam;
  }
  const meta: Record<string, unknown> = { recordCount, source };
  if (schema !== null) meta.schema = schema;
  return { ranges, rangeSections: { f0: [] }, rosters: { f0: ["a"] }, enumOverrides: {}, cabIrs: {}, meta };
}

/** What the database would compute: (family, id) pairs in `ranges` (the SQL is verified by the pgTAP suite). */
function rowCountOf(doc: { ranges: Record<string, Record<string, unknown>> }): number {
  return Object.values(doc.ranges).reduce((n, fam) => n + Object.keys(fam).length, 0);
}

interface Stored extends ProfileRow {
  row_count: number | null;
  created_by: string;
}

let seq = 0;
function stored(o: Partial<Stored> & { source: Stored["source"]; created_at: string }): Stored {
  const doc = (o.profile as ReturnType<typeof profileDoc> | undefined) ?? profileDoc({ source: o.source === "live-walk" ? "live" : "bytes" });
  return {
    id: `00000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`,
    model: 17,
    firmware: "13.0",
    content_hash: `hash-${seq}`,
    profile: doc,
    record_count: 10,
    row_count: rowCountOf(doc),
    created_by: USER,
    ...o
  };
}

// ── fake store: PostgREST-ish filter + ORDER BY over the handler's terms ──

function compare(a: Stored, b: Stored, terms: readonly OrderTerm[]): number {
  for (const t of terms) {
    const av = a[t.column];
    const bv = b[t.column];
    if (av === bv) continue;
    // NULLs: first or last as asked, independent of the direction (PostgreSQL's NULLS FIRST / LAST).
    if (av === null) return t.nullsFirst ? -1 : 1;
    if (bv === null) return t.nullsFirst ? 1 : -1;
    const c = (av as number) < (bv as number) ? -1 : 1; // plain code-point order (strings and numbers alike); matches the database for these ASCII values
    return t.ascending ? c : -c;
  }
  return 0;
}

function metaSchema(r: Stored): number | null {
  const s = (r.profile.meta as Record<string, unknown> | undefined)?.schema;
  return typeof s === "number" ? s : null;
}

function makeDeps(rows: Stored[]) {
  const calls = { filters: [] as ProfileFilter[], auth: [] as string[], counts: [] as Array<[string, string]>, inserts: [] as NewProfile[] };
  const state = { recent: 0, selectError: null as string | null, insertError: null as string | null };
  const deps: Deps = {
    authenticate: (authorization) => {
      calls.auth.push(authorization);
      if (authorization === TOKEN) return Promise.resolve({ id: USER, isAnonymous: false });
      if (authorization === TOKEN_ANON) return Promise.resolve({ id: ANON, isAnonymous: true });
      return Promise.resolve(null);
    },
    selectBestProfile: (f) => {
      calls.filters.push(f);
      if (state.selectError) return Promise.reject(new Error(state.selectError));
      const eligible = rows.filter((r) => {
        if (r.model !== f.model || r.firmware !== f.firmware) return false;
        const s = metaSchema(r);
        return f.schema !== null ? s === f.schema : s === null || f.legacySchemas.includes(s);
      });
      eligible.sort((a, b) => compare(a, b, f.order));
      return Promise.resolve(eligible[0] ?? null);
    },
    countRecentInserts: (userId, sinceIso) => {
      calls.counts.push([userId, sinceIso]);
      return Promise.resolve(state.recent);
    },
    insertProfile: (row) => {
      calls.inserts.push(row);
      if (state.insertError) return Promise.reject(new Error(state.insertError));
      if (rows.some((r) => r.model === row.model && r.firmware === row.firmware && r.content_hash === row.content_hash)) {
        return Promise.resolve<InsertResult>({ kind: "duplicate" });
      }
      const s: Stored = { id: `00000000-0000-4000-8000-${String(++seq).padStart(12, "0")}`, row_count: rowCountOf(row.profile as never), created_at: new Date(NOW).toISOString(), ...row };
      rows.push(s);
      return Promise.resolve<InsertResult>({
        kind: "inserted",
        row: { id: s.id, model: s.model, firmware: s.firmware, content_hash: s.content_hash, source: s.source, created_at: s.created_at }
      });
    }
  };
  return { deps, calls, state, rows };
}

const get = (qs: string) => new Request(`${BASE}?${qs}`);
function post(body: unknown, authorization: string | null = TOKEN): Request {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (authorization !== null) headers.authorization = authorization;
  return new Request(BASE, { method: "POST", headers, body: typeof body === "string" ? body : JSON.stringify(body) });
}
const bodyOf = async (res: Response) => JSON.parse(await res.text());
const uploadBody = (over: Record<string, unknown> = {}) => ({ model: 17, firmware: "13.0", source: "editor-cache", profile: profileDoc(), ...over });

// ─────────────────────────────────────────── ranking (GET) ───────────────────────────────────────────

Deno.test("the ranking terms are editor-cache first, then row_count descending, then OLDEST — never newest", () => {
  assertEquals(PROFILE_ORDER.map((t) => [t.column, t.ascending, t.nullsFirst]), [
    ["source", true, false],
    ["row_count", false, false],
    ["created_at", true, false]
  ]);
  // `source asc` is the editor-cache-first term only because of alphabetical order over exactly these two values
  // (the table check allows no others; the pgTAP suite pins that side).
  assert("editor-cache" < "live-walk");
});

Deno.test("GET asks the store for the ranking, with the schema filter as before", async () => {
  const { deps, calls } = makeDeps([stored({ source: "editor-cache", created_at: "2026-11-01T00:00:00Z" })]);
  await handleRequest(get("model=17&firmware=13.0"), deps, CFG);
  await handleRequest(get("model=17&firmware=13.0&schema=2"), deps, CFG);
  assertEquals(calls.filters, [
    { model: 17, firmware: "13.0", schema: null, legacySchemas: LEGACY_SCHEMAS, order: PROFILE_ORDER },
    { model: 17, firmware: "13.0", schema: 2, legacySchemas: LEGACY_SCHEMAS, order: PROFILE_ORDER }
  ]);
  assertEquals(LEGACY_SCHEMAS, [0, 1]);
});

Deno.test("a NEWER truncated live walk never displaces an older complete editor-cache profile", async () => {
  const complete = stored({ source: "editor-cache", created_at: "2026-11-01T00:00:00Z", profile: profileDoc({ families: 4, ids: 50, source: "bytes" }) });
  const truncatedLive = stored({ source: "live-walk", created_at: "2026-11-20T00:00:00Z", profile: profileDoc({ families: 1, ids: 2, source: "live" }) });
  const bigLive = stored({ source: "live-walk", created_at: "2026-11-21T00:00:00Z", profile: profileDoc({ families: 9, ids: 99, source: "live" }) });
  const { deps } = makeDeps([truncatedLive, bigLive, complete]);
  const res = await handleRequest(get("model=17&firmware=13.0"), deps, CFG);
  assertEquals(res.status, 200);
  // even a live walk with MORE ranges does not outrank the editor-cache profile: the source comes first
  assertEquals((await bodyOf(res)).id, complete.id);
});

Deno.test("without an editor-cache profile the live walk with the most ranges wins, not the newest", async () => {
  const small = stored({ source: "live-walk", created_at: "2026-11-25T00:00:00Z", profile: profileDoc({ families: 1, ids: 5, source: "live" }) });
  const big = stored({ source: "live-walk", created_at: "2026-11-01T00:00:00Z", profile: profileDoc({ families: 3, ids: 40, source: "live" }) });
  const { deps } = makeDeps([small, big]);
  assertEquals((await bodyOf(await handleRequest(get("model=17&firmware=13.0"), deps, CFG))).id, big.id);
});

Deno.test("among editor-cache profiles more ranges win, even a newer or a much older one", async () => {
  const mid = stored({ source: "editor-cache", created_at: "2026-11-10T00:00:00Z", profile: profileDoc({ families: 2, ids: 20 }) });
  const olderSmaller = stored({ source: "editor-cache", created_at: "2026-10-01T00:00:00Z", profile: profileDoc({ families: 1, ids: 3 }) });
  const newerBigger = stored({ source: "editor-cache", created_at: "2026-11-30T00:00:00Z", profile: profileDoc({ families: 5, ids: 30 }) });
  const { deps } = makeDeps([mid, olderSmaller, newerBigger]);
  assertEquals((await bodyOf(await handleRequest(get("model=17&firmware=13.0"), deps, CFG))).id, newerBigger.id);
});

Deno.test("on equal source and row_count the OLDEST row stays", async () => {
  const doc = profileDoc({ families: 2, ids: 7 });
  const newest = stored({ source: "editor-cache", created_at: "2026-11-30T00:00:00Z", profile: doc });
  const oldest = stored({ source: "editor-cache", created_at: "2026-11-01T00:00:00Z", profile: doc });
  const middle = stored({ source: "editor-cache", created_at: "2026-11-15T00:00:00Z", profile: doc });
  const { deps } = makeDeps([newest, middle, oldest]);
  assertEquals((await bodyOf(await handleRequest(get("model=17&firmware=13.0"), deps, CFG))).id, oldest.id);
});

Deno.test("a row without a server row_count ranks after one with it (NULLS LAST)", async () => {
  const counted = stored({ source: "editor-cache", created_at: "2026-11-30T00:00:00Z", row_count: 1 });
  const uncounted = stored({ source: "editor-cache", created_at: "2026-11-01T00:00:00Z", row_count: null });
  const { deps } = makeDeps([uncounted, counted]);
  assertEquals((await bodyOf(await handleRequest(get("model=17&firmware=13.0"), deps, CFG))).id, counted.id);
});

Deno.test("the schema filter still picks the best row OF THAT SCHEMA; legacy clients see unstamped and schema <= 1 only", async () => {
  const unstamped = stored({ source: "live-walk", created_at: "2026-11-01T00:00:00Z", profile: profileDoc({ source: "live", ids: 3 }) });
  const s1 = stored({ source: "editor-cache", created_at: "2026-11-02T00:00:00Z", profile: profileDoc({ schema: 1, ids: 3 }) });
  const s2a = stored({ source: "live-walk", created_at: "2026-11-03T00:00:00Z", profile: profileDoc({ source: "live", schema: 2, ids: 9 }) });
  const s2b = stored({ source: "editor-cache", created_at: "2026-11-04T00:00:00Z", profile: profileDoc({ schema: 2, ids: 2 }) });
  const { deps } = makeDeps([unstamped, s1, s2a, s2b]);
  const idOf = async (qs: string) => (await bodyOf(await handleRequest(get(qs), deps, CFG))).id;
  assertEquals(await idOf("model=17&firmware=13.0"), s1.id); // old client: editor-cache schema 1 over the unstamped live walk
  assertEquals(await idOf("model=17&firmware=13.0&schema=1"), s1.id);
  assertEquals(await idOf("model=17&firmware=13.0&schema=2"), s2b.id); // editor-cache first, not the bigger live walk
  assertEquals((await handleRequest(get("model=17&firmware=13.0&schema=3"), deps, CFG)).status, 404);
  assertEquals((await handleRequest(get("model=18&firmware=13.0"), deps, CFG)).status, 404);
  assertEquals((await handleRequest(get("model=17&firmware=12.0"), deps, CFG)).status, 404);
});

// ─────────────────────────────────────────── GET responses ───────────────────────────────────────────

Deno.test("GET answers with exactly the v1 columns (row_count and anything else stay out) and the cache header", async () => {
  const row = stored({ source: "editor-cache", created_at: "2026-11-01T00:00:00Z" });
  const { deps } = makeDeps([row]);
  const res = await handleRequest(get("model=17&firmware=13.0"), deps, CFG);
  assertEquals(res.status, 200);
  assertEquals(res.headers.get("Cache-Control"), "public, max-age=300");
  assertEquals(res.headers.get("Content-Type"), "application/json");
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "*");
  const out = await bodyOf(res);
  assertEquals(Object.keys(out).sort(), [...RESPONSE_COLUMNS].sort());
  assertEquals(RESPONSE_COLUMNS, ["id", "model", "firmware", "content_hash", "profile", "source", "record_count", "created_at"]);
  assertEquals(out.profile, row.profile);
  assertEquals(out.source, "editor-cache");
  assertFalse("row_count" in out);
  assertFalse("created_by" in out);
});

Deno.test("GET validates model, firmware and schema", async () => {
  const { deps, calls } = makeDeps([]);
  for (const qs of ["", "model=17", "firmware=13.0", "model=0&firmware=13.0", "model=256&firmware=13.0", "model=1.5&firmware=13.0", "model=abc&firmware=13.0", "model=17&firmware="]) {
    const res = await handleRequest(get(qs), deps, CFG);
    assertEquals(res.status, 400, qs);
    assertEquals((await bodyOf(res)).error, "bad request: model (1..255) and firmware required", qs);
  }
  for (const schema of ["0", "-1", "x", "1.5", "1000001", "12345678", ""]) {
    const res = await handleRequest(get(`model=17&firmware=13.0&schema=${schema}`), deps, CFG);
    assertEquals(res.status, 400, `schema=${schema}`);
    assertEquals((await bodyOf(res)).error, "bad request: schema must be an integer 1..1000000");
  }
  assertEquals(calls.filters.length, 0); // none of them reached the store
  assertEquals((await handleRequest(get("model=17&firmware=13.0&schema=1000000"), deps, CFG)).status, 404);
  assertEquals((await handleRequest(get("model=255&firmware=13.0&schema=1"), deps, CFG)).status, 404);
});

Deno.test("GET: a database error is a 500 with its message; unknown methods 405; OPTIONS answers CORS", async () => {
  const { deps, state } = makeDeps([]);
  state.selectError = "boom";
  const res = await handleRequest(get("model=17&firmware=13.0"), deps, CFG);
  assertEquals(res.status, 500);
  assertEquals(await bodyOf(res), { error: "boom" });
  assertEquals((await handleRequest(new Request(BASE, { method: "DELETE" }), deps, CFG)).status, 405);
  const opt = await handleRequest(new Request(BASE, { method: "OPTIONS" }), deps, CFG);
  assertEquals(opt.status, 200);
  assertEquals(opt.headers.get("Access-Control-Allow-Methods"), "GET, POST, OPTIONS");
  assertEquals(opt.headers.get("Access-Control-Allow-Headers"), "authorization, content-type, apikey, x-client-info");
});

// ─────────────────────────────────────────── POST ───────────────────────────────────────────

Deno.test("POST needs a valid session: 401 without one, 403 for an anonymous session (nothing else is touched)", async () => {
  const { deps, calls } = makeDeps([]);
  assertEquals((await handleRequest(post(uploadBody(), null), deps, CFG)).status, 401);
  assertEquals((await handleRequest(post(uploadBody(), "Bearer nope"), deps, CFG)).status, 401);
  const anon = await handleRequest(post(uploadBody(), TOKEN_ANON), deps, CFG);
  assertEquals(anon.status, 403);
  assertEquals(await bodyOf(anon), { error: "account-required" });
  assertEquals(calls.counts.length + calls.inserts.length, 0);
  assertEquals(calls.auth, ["", "Bearer nope", TOKEN_ANON]); // the Authorization header goes through verbatim
});

Deno.test("POST body caps: declared length and actual length, both 413", async () => {
  const { deps, calls } = makeDeps([]);
  const declared = post(uploadBody());
  Object.defineProperty(declared, "headers", { value: new Headers({ authorization: TOKEN, "content-length": String(6 * 1024 * 1024 + 1) }) });
  assertEquals((await handleRequest(declared, deps, CFG)).status, 413);
  const small: HandlerConfig = { ...CFG, maxBodyBytes: 100 };
  const actual = await handleRequest(post(uploadBody()), deps, small);
  assertEquals(actual.status, 413);
  assertEquals(await bodyOf(actual), { error: "payload too large" });
  assertEquals(calls.inserts.length, 0);
});

Deno.test("POST validation answers 400 with the v1 messages", async () => {
  const { deps, calls } = makeDeps([]);
  const cases: Array<[string, unknown, string]> = [
    ["not JSON", "not json {", "invalid JSON"],
    ["JSON null", "null", "body must be a JSON object"],
    ["JSON array", "[]", "body must be a JSON object"],
    ["model missing", uploadBody({ model: undefined }), "model must be an integer 1..255"],
    ["model string", uploadBody({ model: "17" }), "model must be an integer 1..255"],
    ["model 0", uploadBody({ model: 0 }), "model must be an integer 1..255"],
    ["model 256", uploadBody({ model: 256 }), "model must be an integer 1..255"],
    ["model fraction", uploadBody({ model: 1.5 }), "model must be an integer 1..255"],
    ["firmware shape", uploadBody({ firmware: "latest" }), "firmware must match \\d+\\.\\d+"],
    ["firmware number", uploadBody({ firmware: 13 }), "firmware must match \\d+\\.\\d+"],
    ["source", uploadBody({ source: "manual" }), "source must be 'live-walk' or 'editor-cache'"],
    ["profile not object", uploadBody({ profile: [] }), "profile must be an object"],
    ["ranges empty", uploadBody({ profile: { ...profileDoc(), ranges: {} } }), "profile.ranges missing or empty"],
    ["rangeSections empty", uploadBody({ profile: { ...profileDoc(), rangeSections: {} } }), "profile.rangeSections missing or empty"],
    ["rosters missing", uploadBody({ profile: { ...profileDoc(), rosters: undefined } }), "profile.rosters missing or empty"],
    ["enumOverrides", uploadBody({ profile: { ...profileDoc(), enumOverrides: [] } }), "profile.enumOverrides must be an object"],
    ["cabIrs", uploadBody({ profile: { ...profileDoc(), cabIrs: null } }), "profile.cabIrs must be an object"],
    ["meta", uploadBody({ profile: { ...profileDoc(), meta: 1 } }), "profile.meta must be an object"],
    ["recordCount", uploadBody({ profile: { ...profileDoc(), meta: { source: "bytes", recordCount: "10" } } }), "profile.meta.recordCount must be a number"],
    ["meta.source", uploadBody({ profile: { ...profileDoc(), meta: { source: "x", recordCount: 1 } } }), "profile.meta.source invalid"],
    ["kind mismatch", uploadBody({ source: "live-walk" }), "source 'live-walk' does not match profile.meta.source 'bytes'"],
    ["kind mismatch 2", uploadBody({ source: "editor-cache", profile: profileDoc({ source: "live" }) }), "source 'editor-cache' does not match profile.meta.source 'live'"]
  ];
  for (const [name, body, error] of cases) {
    const res = await handleRequest(post(body), deps, CFG);
    assertEquals(res.status, 400, name);
    assertEquals((await bodyOf(res)).error, error, name);
  }
  assertEquals(calls.counts.length, 0); // no rate-limit query, no insert, for any rejected body
  assertEquals(calls.inserts.length, 0);
  assertEquals(validateProfile(profileDoc()), null);
});

Deno.test("POST rate limit: 10 new profiles per rolling hour, counted from the injected clock", async () => {
  const { deps, calls, state } = makeDeps([]);
  state.recent = 9;
  assertEquals((await handleRequest(post(uploadBody()), deps, CFG)).status, 201);
  assertEquals(calls.counts, [[USER, new Date(NOW - HOUR).toISOString()]]);
  state.recent = 10;
  const limited = await handleRequest(post(uploadBody({ firmware: "13.1" })), deps, CFG);
  assertEquals(limited.status, 429);
  assertEquals(await bodyOf(limited), { error: "rate limited" });
  assertEquals(calls.inserts.length, 1); // the limited request inserted nothing
});

Deno.test("POST inserts the server-computed hash and the plain columns only (a client-sent row_count/hash/created_by is ignored)", async () => {
  const { deps, calls, rows } = makeDeps([]);
  const doc = profileDoc({ families: 2, ids: 2, recordCount: 7 });
  const res = await handleRequest(
    post({ ...uploadBody({ profile: doc }), row_count: 999999, content_hash: "client-hash", created_by: ANON, id: "x", created_at: "1999-01-01" }),
    deps,
    CFG
  );
  assertEquals(res.status, 201);
  assertEquals(calls.inserts.length, 1);
  const ins = calls.inserts[0];
  assertEquals(Object.keys(ins).sort(), ["content_hash", "created_by", "firmware", "model", "profile", "record_count", "source"]);
  assertEquals(ins.created_by, USER);
  assertEquals(ins.record_count, 7);
  assertNotEquals(ins.content_hash, "client-hash");
  assertEquals(ins.content_hash, await sha256(canonicalJson(doc)));
  assertEquals(rows[0].row_count, 4); // what the database computes: 2 families x 2 ids
  const out = await bodyOf(res);
  assertEquals(Object.keys(out).sort(), ["content_hash", "created_at", "firmware", "id", "model", "ok", "source"]);
  assertEquals(out.ok, true);
  assertEquals(out.content_hash, ins.content_hash);
});

async function sha256(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.test("POST hashes the canonical JSON: key order does not matter, content does; a repeat is deduped", async () => {
  assertEquals(canonicalJson({ b: [1, { d: 1, c: 2 }], a: null }), '{"a":null,"b":[1,{"c":2,"d":1}]}');
  const { deps, calls } = makeDeps([]);
  const doc = profileDoc();
  const reordered = JSON.parse(JSON.stringify({ meta: doc.meta, cabIrs: doc.cabIrs, enumOverrides: doc.enumOverrides, rosters: doc.rosters, rangeSections: doc.rangeSections, ranges: doc.ranges }));
  const first = await handleRequest(post(uploadBody({ profile: doc })), deps, CFG);
  assertEquals(first.status, 201);
  const second = await handleRequest(post(uploadBody({ profile: reordered })), deps, CFG);
  assertEquals(second.status, 200);
  assertEquals(await bodyOf(second), { deduped: true, contentHash: calls.inserts[0].content_hash });
  assertEquals(calls.inserts[1].content_hash, calls.inserts[0].content_hash);
  // different content: its own row
  const changed = profileDoc({ ids: 4 });
  const third = await handleRequest(post(uploadBody({ profile: changed })), deps, CFG);
  assertEquals(third.status, 201);
  assertNotEquals(calls.inserts[2].content_hash, calls.inserts[0].content_hash);
});

Deno.test("POST: an insert failure is a 500 with its message", async () => {
  const { deps, state } = makeDeps([]);
  state.insertError = "insert failed";
  const res = await handleRequest(post(uploadBody()), deps, CFG);
  assertEquals(res.status, 500);
  assertEquals(await bodyOf(res), { error: "insert failed" });
});

Deno.test("a POSTed live walk does not displace a stored editor-cache profile on the next GET (end to end through the seam)", async () => {
  const cache = stored({ source: "editor-cache", created_at: "2026-11-01T00:00:00Z", profile: profileDoc({ families: 4, ids: 25, source: "bytes" }) });
  const { deps } = makeDeps([cache]);
  const live = profileDoc({ families: 1, ids: 3, source: "live" });
  const up = await handleRequest(post(uploadBody({ source: "live-walk", profile: live })), deps, CFG);
  assertEquals(up.status, 201);
  const got = await bodyOf(await handleRequest(get("model=17&firmware=13.0"), deps, CFG));
  assertEquals(got.id, cache.id);
  assertEquals(got.source, "editor-cache");
});
