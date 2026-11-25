// Unit tests for the editor-caches edge function (signed-upload flow). Run with:
//   deno test supabase/functions/editor-caches/
// No Supabase stack or network is needed: handler.ts talks to the database and storage only through `Deps`, which
// these tests replace with in-memory fakes. What they therefore do NOT cover — and what needs a local-stack run —
// is everything behind that seam: the SQL functions (atomic limits, dedup, coverage; see
// supabase/tests/database/editor_cache_uploads.test.sql), the Supabase adapter in index.ts and the bucket limits.
// The fake `reserve`/`complete` below only mimic the SQL semantics so the handler's mapping can be asserted.
// Synthetic caches only (synthetic-cache.ts) — never real files.
import { assert, assertEquals, assertMatch } from "jsr:@std/assert@1";
import {
  type CompleteArgs,
  type CoverageState,
  DEFAULT_CONFIG,
  type Deps,
  type HandlerConfig,
  handleRequest,
  type ReserveArgs,
  type ReserveResult,
  type UploadSummary
} from "./handler.ts";
import { blank, cache, enumRec, section, typicalCache } from "./synthetic-cache.ts";
import { MIN_CONSENT_VERSION, objectPath, sha256Hex } from "./validate.ts";

const USER = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const ANON = "33333333-3333-4333-8333-333333333333";
const ANON2 = "44444444-4444-4444-8444-444444444444";
const NOW = Date.parse("2026-11-23T10:00:00Z");
const TOKEN = "hdr.payload.user";
const TOKEN_OTHER = "hdr.payload.other";
const TOKEN_ANON = "hdr.payload.anon";
const TOKEN_ANON2 = "hdr.payload.anon2";
const TOKEN_UNKNOWN = "hdr.payload.unknown";
const IP = "203.0.113.7";
const SALT = "test-salt-0123456789abcdef0123456789abcdef"; // ≥ 32 chars, like a real one must be
const logged: Array<[string, string]> = [];
const CFG: HandlerConfig = { ...DEFAULT_CONFIG, ipSalt: SALT, now: () => NOW, log: (level, msg) => void logged.push([level, msg]) };

// ── fakes ──

interface Row {
  id: string;
  userId: string;
  model: number;
  deviceFirmware: string;
  fileVersion: string | null;
  contentVersion: string | null;
  fileName: string;
  sha256: string;
  bytes: number;
  status: "pending" | "complete";
  objectPath: string;
  createdAt: number;
  consentVersion: number;
}

interface IpRow {
  ipKey: string;
  uploadId: string | null;
  bytes: number | null;
  createdAt: number;
}

const versionMatch = (r: Row) => r.fileVersion === r.deviceFirmware || r.contentVersion === r.deviceFirmware;
const covKey = (model: number, fw: string) => `${model}/${fw}`;

function makeDeps() {
  const rows: Row[] = [];
  const ipUsage: IpRow[] = [];
  const coverage = new Map<string, { state: CoverageState; contributors: number; reopenedAt: number | null }>();
  const objects = new Map<string, Uint8Array>();
  const reserveCalls: ReserveArgs[] = [];
  const completeCalls: CompleteArgs[] = [];
  const removed: string[] = [];
  const state = { now: NOW, seq: 0, authCalls: 0 };

  const unlink = (id: string) => ipUsage.forEach((l) => l.uploadId === id && (l.uploadId = null));
  const dropRow = (r: Row) => {
    rows.splice(rows.indexOf(r), 1);
    unlink(r.id);
  };

  const deps: Deps = {
    authenticate: (t) => {
      state.authCalls++;
      const map: Record<string, { id: string; isAnonymous: boolean }> = {
        [TOKEN]: { id: USER, isAnonymous: false },
        [TOKEN_OTHER]: { id: OTHER, isAnonymous: false },
        [TOKEN_ANON]: { id: ANON, isAnonymous: true },
        [TOKEN_ANON2]: { id: ANON2, isAnonymous: true }
      };
      return Promise.resolve(map[t] ?? null);
    },

    coverageState: (model, fw) => Promise.resolve(coverage.get(covKey(model, fw))?.state ?? null),

    // Mimics reserve_editor_cache_upload (the SQL is authoritative — see the pgTAP file).
    reserve: (a): Promise<ReserveResult> => {
      reserveCalls.push(a);
      const own = rows.find((r) => r.userId === a.userId && r.sha256 === a.sha256);
      let refresh: Row | null = null;
      if (own) {
        if (own.status === "complete") return Promise.resolve({ kind: "ok", id: own.id, status: "complete", deduped: true });
        if (state.now - own.createdAt > a.pendingMaxAgeSeconds * 1000) dropRow(own);
        else if (objects.has(own.objectPath)) return Promise.resolve({ kind: "ok", id: own.id, status: "pending", deduped: true });
        else refresh = own;
      }
      const cross = rows.find((r) =>
        r.userId !== a.userId && r.model === a.model && r.deviceFirmware === a.deviceFirmware && r.sha256 === a.sha256 && r.status === "complete"
      );
      if (cross) {
        if (refresh) dropRow(refresh);
        return Promise.resolve({ kind: "ok", id: null, status: "complete", deduped: true });
      }
      const cov = coverage.get(covKey(a.model, a.deviceFirmware));
      if (cov && cov.state !== "collecting") return Promise.resolve({ kind: "not-wanted" });
      const inWindow = (t: number, secs: number) => t > state.now - secs * 1000;
      if (!refresh) {
        const sameFw = rows.filter((r) => r.userId === a.userId && r.model === a.model && r.deviceFirmware === a.deviceFirmware);
        if (sameFw.length >= a.perFirmwareMax) return Promise.resolve({ kind: "firmware-limit" });
        if (rows.filter((r) => r.userId === a.userId && inWindow(r.createdAt, a.windowSeconds)).length >= a.maxPerWindow) {
          return Promise.resolve({ kind: "limited", reason: "rate", scope: "uploader", retryAfterSeconds: 1234 });
        }
        if (ipUsage.filter((l) => l.ipKey === a.ipKey && inWindow(l.createdAt, a.windowSeconds)).length >= a.ipMaxPerWindow) {
          return Promise.resolve({ kind: "limited", reason: "rate", scope: "ip", retryAfterSeconds: 2345 });
        }
      }
      const used = rows
        .filter((r) => r.userId === a.userId && inWindow(r.createdAt, a.quotaWindowSeconds) && r !== refresh)
        .reduce((s, r) => s + (r.status === "pending" ? a.pendingChargeBytes : r.bytes), 0);
      if (used + a.bytes > a.quotaBytes) return Promise.resolve({ kind: "limited", reason: "quota", scope: "uploader", retryAfterSeconds: 3456 });
      const ipUsed = ipUsage
        .filter((l) => l.ipKey === a.ipKey && inWindow(l.createdAt, a.quotaWindowSeconds) && (!refresh || l.uploadId !== refresh.id))
        .reduce((s, l) => {
          const linked = l.uploadId ? rows.find((r) => r.id === l.uploadId) : undefined;
          return s + (l.bytes ?? (linked?.status === "pending" ? a.pendingChargeBytes : 0));
        }, 0);
      if (ipUsed + a.bytes > a.ipQuotaBytes) return Promise.resolve({ kind: "limited", reason: "quota", scope: "ip", retryAfterSeconds: 4567 });
      if (refresh) {
        refresh.bytes = a.bytes;
        return Promise.resolve({ kind: "ok", id: refresh.id, status: "pending", deduped: true });
      }
      const id = `00000000-0000-4000-8000-${String(++state.seq).padStart(12, "0")}`;
      rows.push({
        id,
        userId: a.userId,
        model: a.model,
        deviceFirmware: a.deviceFirmware,
        fileVersion: a.fileVersion,
        contentVersion: a.contentVersion,
        fileName: a.fileName,
        sha256: a.sha256,
        bytes: a.bytes,
        status: "pending",
        objectPath: objectPath(a.userId, a.sha256),
        createdAt: state.now,
        consentVersion: a.consentVersion
      });
      ipUsage.push({ ipKey: a.ipKey, uploadId: id, bytes: null, createdAt: state.now });
      return Promise.resolve({ kind: "ok", id, status: "pending", deduped: false });
    },

    createUpload: (path) =>
      Promise.resolve(objects.has(path) ? "exists" : { uploadUrl: `https://storage.test/object/upload/sign/editor-caches/${path}?token=T`, token: "T" }),

    getUpload: (u, id) => {
      const r = rows.find((x) => x.id === id && x.userId === u);
      return Promise.resolve(
        r
          ? {
            id: r.id,
            status: r.status,
            bytes: r.bytes,
            objectPath: r.objectPath,
            sha256: r.sha256,
            model: r.model,
            deviceFirmware: r.deviceFirmware,
            fileVersion: r.fileVersion,
            contentVersion: r.contentVersion
          }
          : null
      );
    },
    statObject: (p) => Promise.resolve(objects.has(p) ? { size: objects.get(p)!.length } : null),
    readObject: (p, n) => Promise.resolve(objects.has(p) ? objects.get(p)!.slice(0, n) : null),

    // Mimics complete_editor_cache_upload.
    complete: (a) => {
      completeCalls.push(a);
      const r = rows.find((x) => x.id === a.rowId && x.userId === a.userId);
      if (!r) return Promise.resolve(null);
      const k = covKey(r.model, r.deviceFirmware);
      if (r.status === "complete") {
        const st = coverage.get(k)?.state;
        return Promise.resolve({ status: "complete", covered: st !== undefined && st !== "collecting" });
      }
      r.status = "complete";
      r.bytes = a.bytes;
      r.contentVersion = a.contentVersion;
      ipUsage.forEach((l) => l.uploadId === r.id && (l.bytes = a.bytes));
      if (versionMatch(r)) {
        // least(distinct uploaders, distinct network keys) over complete, version-matched uploads with a counter
        const since = coverage.get(k)?.reopenedAt ?? null;
        const counted = rows.filter((x) =>
          x.model === r.model && x.deviceFirmware === r.deviceFirmware && x.status === "complete" && versionMatch(x) &&
          (since === null || x.createdAt >= since) && ipUsage.some((l) => l.uploadId === x.id)
        );
        const nets = new Set(counted.map((x) => ipUsage.find((l) => l.uploadId === x.id)!.ipKey)).size;
        const users = Math.min(new Set(counted.map((x) => x.userId)).size, nets);
        const cur = coverage.get(k) ?? { state: "collecting" as CoverageState, contributors: 0, reopenedAt: null };
        const contributors = Math.max(cur.contributors, users);
        coverage.set(k, { ...cur, contributors, state: cur.state === "collecting" && contributors >= a.threshold ? "covered" : cur.state });
      }
      const st = coverage.get(k)?.state;
      return Promise.resolve({ status: "complete", covered: st !== undefined && st !== "collecting" });
    },

    removeObject: (p) => {
      objects.delete(p);
      removed.push(p);
      return Promise.resolve();
    },
    deleteUpload: (u, id) => {
      const r = rows.find((x) => x.id === id && x.userId === u);
      if (!r) return Promise.resolve(false);
      dropRow(r);
      return Promise.resolve(true);
    },
    listUploads: (u, limit) =>
      Promise.resolve(
        rows.filter((r) => r.userId === u).slice(0, limit).map((r): UploadSummary => ({
          uploadId: r.id,
          model: r.model,
          deviceFirmware: r.deviceFirmware,
          fileVersion: r.fileVersion,
          contentVersion: r.contentVersion,
          versionMatch: versionMatch(r),
          fileName: r.fileName,
          sha256: r.sha256,
          bytes: r.bytes,
          status: r.status,
          createdAt: new Date(r.createdAt).toISOString(),
          expiresAt: new Date(r.createdAt + 180 * 86400_000).toISOString()
        }))
      )
  };
  return { deps, rows, ipUsage, coverage, objects, reserveCalls, completeCalls, removed, state };
}

type H = ReturnType<typeof makeDeps>;

// ── request helpers ──

interface File {
  bytes: Uint8Array;
  sha: string;
  name: string;
  fileVersion: string;
}

async function file(bytes: Uint8Array, name = "effectDefinitions_11_13p0.cache", fileVersion = "13.0"): Promise<File> {
  return { bytes, sha: await sha256Hex(bytes), name, fileVersion };
}

/** A second, different valid 13.0 cache (another unit's file: one more parameter record). */
function otherCache13(): Uint8Array {
  return typicalCache(13, 0, true, {}, true);
}

function req(method: string, suffix: string, body?: unknown, headers: Record<string, string> = {}, token: string | null = TOKEN): Request {
  const h: Record<string, string> = { "content-type": "application/json", "x-real-ip": IP, ...headers };
  if (token) h.authorization = `Bearer ${token}`;
  return new Request(`http://localhost/editor-caches${suffix}`, {
    method,
    headers: h,
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body)
  });
}

function reserveBody(f: File, over: Record<string, unknown> = {}) {
  return {
    model: 17,
    deviceFirmware: "13.0",
    fileVersion: f.fileVersion,
    contentVersion: null,
    fileName: f.name,
    sha256: f.sha,
    bytes: f.bytes.length,
    redaction: { version: 1, tables: 2, names: 6 },
    summary: { sections: 3, records: 9, unmappedSections: 0, suspectFamilies: [], agreement: 1, extra: "dropped" },
    app: { forgefx: "0.9.0-beta", codec: "0.7.0", axis: "0.11.0-beta", host: "dropped" },
    consentAt: "2026-11-23T09:58:00.000Z",
    consentVersion: MIN_CONSENT_VERSION,
    ...over
  };
}

async function call(h: H, r: Request, cfg: HandlerConfig = CFG) {
  const res = await handleRequest(r, h.deps, cfg);
  return { res, body: await res.json().catch(() => null) as Record<string, unknown> | null };
}

async function reserve(h: H, f: File, token = TOKEN, over: Record<string, unknown> = {}, headers: Record<string, string> = {}, cfg = CFG) {
  return await call(h, req("POST", "", reserveBody(f, over), headers, token), cfg);
}

async function finalize(h: H, uploadId: unknown, token = TOKEN, cfg = CFG) {
  return await call(h, req("POST", "/finalize", { uploadId }, {}, token), cfg);
}

/** Reserve, then simulate the client's storage upload of `stored` (default: the file itself). */
async function reserveAndUpload(h: H, f: File, token = TOKEN, stored?: Uint8Array, headers: Record<string, string> = {}) {
  const { body } = await reserve(h, f, token, {}, headers);
  assertEquals(body?.status, "pending", JSON.stringify(body));
  h.objects.set(body!.path as string, stored ?? f.bytes);
  return body!.uploadId as string;
}

async function quiet<T>(fn: () => Promise<T>): Promise<T> {
  const orig = console.error;
  console.error = () => {};
  try {
    return await fn();
  } finally {
    console.error = orig;
  }
}

// ── protocol ──

Deno.test("OPTIONS answers the CORS preflight (GET + POST) and exposes Retry-After", async () => {
  const h = makeDeps();
  const res = await handleRequest(new Request("http://localhost/x", { method: "OPTIONS" }), h.deps, CFG);
  assertEquals(res.status, 200);
  assertEquals(res.headers.get("access-control-allow-methods"), "GET, POST, OPTIONS");
  assertEquals(res.headers.get("access-control-expose-headers"), "Retry-After");
});

Deno.test("other methods are refused (405)", async () => {
  const h = makeDeps();
  const { res } = await call(h, req("PUT", "", {}));
  assertEquals(res.status, 405);
  assertEquals(res.headers.get("allow"), "GET, POST, OPTIONS");
});

// ── public status ──

Deno.test("GET status: public, cacheable, answers only { model, firmware, wanted }", async () => {
  const h = makeDeps();
  const get = (q: string, cfg = CFG) => call(h, req("GET", `?${q}`, undefined, {}, null), cfg);
  let r = await get("model=17&firmware=13.0");
  assertEquals(r.res.status, 200);
  assertEquals(r.body, { model: 17, firmware: "13.0", wanted: true });
  assertEquals(r.res.headers.get("cache-control"), "public, max-age=600");
  h.coverage.set("17/13.0", { state: "covered", contributors: 2, reopenedAt: null });
  h.coverage.set("17/12.0", { state: "closed", contributors: 0, reopenedAt: null });
  h.coverage.set("16/32.6", { state: "collecting", contributors: 1, reopenedAt: null });
  assertEquals((await get("model=17&firmware=13.0")).body?.wanted, false);
  assertEquals((await get("model=17&firmware=12.0")).body?.wanted, false);
  r = await get("model=16&firmware=32.6");
  assertEquals(r.body, { model: 16, firmware: "32.6", wanted: true }); // no counts, no dates
  assertEquals((await get("model=1&firmware=13.0")).body?.wanted, false, "a model that cannot contribute");
  assertEquals((await get("model=16&firmware=32.6", { ...CFG, enabled: false })).body?.wanted, false, "kill switch");
  assertEquals((await get("model=16&firmware=32.6", { ...CFG, ipSalt: null })).body?.wanted, false, "no network-key secret");
  assertEquals((await get("model=17&firmware=13")).res.status, 400);
  assertEquals((await get("firmware=13.0")).res.status, 400);
  assertEquals(h.state.authCalls, 0);
});

// ── auth ──

Deno.test("401 without a valid bearer token on every authenticated route; nothing is reserved", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  for (const token of [null, TOKEN_UNKNOWN, "not-a-jwt"]) {
    for (const [method, suffix, body] of [["POST", "", reserveBody(f)], ["POST", "/finalize", { uploadId: "x" }], ["POST", "/delete", { uploadId: "x" }], ["GET", "/mine", undefined]] as const) {
      const { res, body: out } = await call(h, req(method, suffix, body, {}, token));
      assertEquals(res.status, 401, `${method} ${suffix}`);
      assertEquals(out, { error: "unauthorized" });
    }
  }
  assertEquals(h.reserveCalls.length, 0);
});

Deno.test("anonymous sessions may upload by default; switched off they get 403 account-required", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  assertEquals((await reserve(h, f, TOKEN_ANON)).res.status, 200);
  assertEquals(h.rows[0].userId, ANON);
  const off = await reserve(h, f, TOKEN_ANON2, {}, {}, { ...CFG, allowAnonymous: false });
  assertEquals(off.res.status, 403);
  assertEquals(off.body?.error, "account-required");
  assertEquals(h.rows.length, 1);
});

Deno.test("switching anonymous uploads off never strands an earlier anonymous uploader: list and delete still work", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const id = await reserveAndUpload(h, f, TOKEN_ANON);
  assertEquals((await finalize(h, id, TOKEN_ANON)).body?.status, "complete");
  const off = { ...CFG, allowAnonymous: false };
  assertEquals((await finalize(h, id, TOKEN_ANON, off)).res.status, 403, "uploading stays refused");
  const mine = await call(h, req("GET", "/mine", undefined, {}, TOKEN_ANON), off);
  assertEquals(mine.res.status, 200);
  assertEquals((mine.body?.uploads as unknown[]).length, 1);
  const del = await call(h, req("POST", "/delete", { uploadId: id }, {}, TOKEN_ANON), off);
  assertEquals(del.body, { uploadId: id, deleted: true });
  assertEquals(h.rows.length, 0);
});

Deno.test("an authentication outage is a 500, not a 401", async () => {
  const h = makeDeps();
  h.deps.authenticate = () => Promise.reject(new Error("auth server unreachable"));
  const { res, body } = await quiet(() => reserve(h, { bytes: new Uint8Array(1), sha: "a".repeat(64), name: "x", fileVersion: "13.0" }));
  assertEquals(res.status, 500);
  assertEquals(body?.error, "internal");
});

// ── kill switch / configuration ──

Deno.test("paused (kill switch or missing secret): reserve and finalize 503, listing and delete still work", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const id = await reserveAndUpload(h, f);
  for (const cfg of [{ ...CFG, enabled: false }, { ...CFG, ipSalt: null }]) {
    assertEquals((await reserve(h, f, TOKEN, {}, {}, cfg)).body?.error, "paused");
    assertEquals((await reserve(h, f, TOKEN, {}, {}, cfg)).res.status, 503);
    assertEquals((await finalize(h, id, TOKEN, cfg)).res.status, 503);
    assertEquals((await call(h, req("GET", "/mine"), cfg)).res.status, 200);
  }
  const del = await call(h, req("POST", "/delete", { uploadId: id }), { ...CFG, enabled: false });
  assertEquals(del.res.status, 200);
  assertEquals(h.rows.length, 0);
});

Deno.test("a network-key secret shorter than 32 characters fails closed (paused, wanted:false)", async () => {
  const h = makeDeps();
  const weak = { ...CFG, ipSalt: "short-secret" };
  assertEquals((await reserve(h, await file(typicalCache()), TOKEN, {}, {}, weak)).body?.error, "paused");
  assertEquals((await call(h, req("GET", "?model=17&firmware=13.0", undefined, {}, null), weak)).body?.wanted, false);
  assertEquals(h.reserveCalls.length, 0);
});

Deno.test("header diagnostic: logged once per isolate with header NAMES and the XFF count only; 'unknown' warns", async () => {
  const { ipDiagnostics } = await import("./handler.ts");
  const h = makeDeps();
  ipDiagnostics.logged = false;
  logged.length = 0;
  const xff = { "x-real-ip": "", "x-forwarded-for": `198.51.100.99, ${IP}` };
  await reserve(h, await file(typicalCache()), TOKEN, {}, xff);
  await reserve(h, await file(otherCache13()), TOKEN, {}, xff);
  const infos = logged.filter(([l]) => l === "info");
  assertEquals(infos.length, 1, "once per isolate");
  assert(infos[0][1].includes("x-forwarded-for") && infos[0][1].includes("entries: 2"));
  // no usable address at all: shared bucket + a warning (still no values)
  await reserve(h, await file(typicalCache(13, 0, true, { buildDate: "u" })), TOKEN_OTHER, {}, { "x-real-ip": "garbage" });
  assertEquals(logged.filter(([l]) => l === "warn").length, 1);
  const all = JSON.stringify(logged);
  for (const v of [IP, "198.51.100.99", "garbage"]) assert(!all.includes(v), `${v} logged`);
});

// ── reserve ──

Deno.test("reserve: pending row + signed upload for <user>/<sha256>.cache, limits and sanitized fields passed on", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const { res, body } = await reserve(h, f);
  assertEquals(res.status, 200);
  const path = `${USER}/${f.sha}.cache`;
  assertEquals(body, {
    uploadId: h.rows[0].id,
    status: "pending",
    uploadUrl: `https://storage.test/object/upload/sign/editor-caches/${path}?token=T`,
    token: "T",
    path,
    bucket: "editor-caches",
    expiresIn: 7200
  });
  const a = h.reserveCalls[0];
  assertMatch(a.ipKey, /^[0-9a-f]{64}$/);
  assertEquals({ ...a, ipKey: "<key>" }, {
    userId: USER,
    ipKey: "<key>",
    model: 17,
    deviceFirmware: "13.0",
    fileVersion: "13.0",
    contentVersion: null,
    fileName: "effectDefinitions_11_13p0.cache",
    sha256: f.sha,
    bytes: f.bytes.length,
    redaction: { version: 1, tables: 2, names: 6 },
    summary: { sections: 3, records: 9, unmappedSections: 0, suspectFamilies: [], agreement: 1 },
    app: { forgefx: "0.9.0-beta", codec: "0.7.0", axis: "0.11.0-beta" },
    consentAt: "2026-11-23T09:58:00.000Z",
    consentVersion: MIN_CONSENT_VERSION,
    maxPerWindow: 5,
    windowSeconds: 3600,
    quotaBytes: 20 * 1024 * 1024,
    quotaWindowSeconds: 30 * 86400,
    pendingChargeBytes: 4 * 1024 * 1024,
    pendingMaxAgeSeconds: 20 * 3600,
    perFirmwareMax: 2,
    ipMaxPerWindow: 5,
    ipQuotaBytes: 20 * 1024 * 1024
  });
});

Deno.test("reserve: the client address never reaches the database — only its keyed hash, per network", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const g = await file(otherCache13());
  await reserve(h, f, TOKEN, {}, { "x-real-ip": IP });
  await reserve(h, g, TOKEN_OTHER, {}, { "x-real-ip": IP });
  await reserve(h, f, TOKEN_ANON, {}, { "x-real-ip": "198.51.100.20" });
  // a spoofed first x-forwarded-for entry is ignored: the last entry is the proxy's
  await reserve(h, g, TOKEN_ANON2, {}, { "x-real-ip": "", "x-forwarded-for": `198.51.100.99, ${IP}` });
  const keys = h.reserveCalls.map((c) => c.ipKey);
  assertEquals(keys[0], keys[1]);
  assert(keys[0] !== keys[2]);
  assertEquals(keys[3], keys[0]);
  const all = JSON.stringify(h.reserveCalls) + JSON.stringify(h.rows) + JSON.stringify(h.ipUsage);
  for (const addr of [IP, "198.51.100.20", "198.51.100.99"]) assert(!all.includes(addr), `${addr} leaked`);
});

Deno.test("reserve: malformed requests are refused before anything is reserved", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const cases: Array<[string, Request, number, string]> = [
    ["invalid json", req("POST", "", "{nope"), 400, "invalid-json"],
    ["empty body", req("POST", "", ""), 400, "empty-body"],
    ["body too large", req("POST", "", { ...reserveBody(f), pad: "x".repeat(9000) }), 413, "too-large"],
    ["no consent", req("POST", "", reserveBody(f, { consentAt: undefined })), 400, "consent-required"],
    ["renamed file", req("POST", "", reserveBody(f, { fileName: "effectDefinitions_11_12p0.cache" })), 400, "invalid-request"],
    ["bytes over the cap", req("POST", "", reserveBody(f, { bytes: 4 * 1024 * 1024 + 1 })), 413, "too-large"],
    ["redaction shape", req("POST", "", reserveBody(f, { redaction: { version: 1, tables: 2, names: 6, bytesReplaced: 1 } })), 400, "invalid-request"]
  ];
  for (const [label, r, status, error] of cases) {
    const { res, body } = await call(h, r);
    assertEquals(res.status, status, label);
    assertEquals(body?.error, error, label);
  }
  assertEquals(h.reserveCalls.length, 0);
});

Deno.test("reserve: a model that cannot contribute and a covered firmware are 409 not-wanted", async () => {
  const h = makeDeps();
  const am = await file(typicalCache(), "effectDefinitions_15_13p0.cache");
  const r1 = await reserve(h, am, TOKEN, { model: 0x15 });
  assertEquals([r1.res.status, r1.body?.error], [409, "not-wanted"]);
  assertEquals(h.reserveCalls.length, 0);
  h.coverage.set("17/13.0", { state: "covered", contributors: 0, reopenedAt: null });
  const r2 = await reserve(h, await file(typicalCache()));
  assertEquals([r2.res.status, r2.body?.error], [409, "not-wanted"]);
  assertEquals(h.rows.length, 0);
});

Deno.test("reserve: at most two uploads per (uploader, model, firmware) — 409 firmware-limit", async () => {
  const h = makeDeps();
  assertEquals((await reserve(h, await file(typicalCache()))).res.status, 200);
  assertEquals((await reserve(h, await file(otherCache13()))).res.status, 200);
  const third = await reserve(h, await file(typicalCache(13, 0, true, { buildDate: "x" })));
  assertEquals([third.res.status, third.body?.error, third.body?.limit], [409, "firmware-limit", 2]);
});

Deno.test("reserve: 429 per uploader and per network, with Retry-After", async () => {
  const h = makeDeps();
  const cfg = { ...CFG, perFirmwareMax: 100 };
  const files = await Promise.all([0, 1, 2, 3, 4, 5].map((i) => file(typicalCache(13, 0, true, { buildDate: `b${i}` }))));
  for (let i = 0; i < 5; i++) assertEquals((await reserve(h, files[i], TOKEN, {}, {}, cfg)).res.status, 200);
  const r = await reserve(h, files[5], TOKEN, {}, { "x-real-ip": "198.51.100.1" }, cfg);
  assertEquals(r.res.status, 429);
  assertEquals(r.body, { error: "rate-limited", scope: "uploader", limit: 5, windowSeconds: 3600, retryAfterSeconds: 1234 });
  assertEquals(r.res.headers.get("retry-after"), "1234");

  // Fresh anonymous ids do not help: the network limit binds (5 per hour from IP, already used above).
  const n = await reserve(h, files[5], TOKEN_ANON, {}, {}, cfg);
  assertEquals(n.res.status, 429);
  assertEquals([n.body?.error, n.body?.scope, n.res.headers.get("retry-after")], ["rate-limited", "ip", "2345"]);
});

Deno.test("reserve: byte quotas map to 429 quota-exceeded with the scope", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const small = { ...CFG, quotaBytes: 10 };
  const q = await reserve(h, f, TOKEN, {}, {}, small);
  assertEquals([q.res.status, q.body?.error, q.body?.scope, q.body?.quotaBytes], [429, "quota-exceeded", "uploader", 10]);
  const ipq = await reserve(h, f, TOKEN, {}, {}, { ...CFG, ipQuotaBytes: 10 });
  assertEquals([ipq.res.status, ipq.body?.error, ipq.body?.scope, ipq.body?.quotaBytes], [429, "quota-exceeded", "ip", 10]);
});

Deno.test("reserve: dedup — own complete, someone else's identical file, and an object already uploaded", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const id = await reserveAndUpload(h, f);
  // object there, not finalized: no new upload URL, finalize only
  let r = await reserve(h, f);
  assertEquals(r.body, { uploadId: id, status: "pending", deduped: true });
  assertEquals((await finalize(h, id)).body?.status, "complete");
  r = await reserve(h, f);
  assertEquals(r.body, { uploadId: id, status: "complete", deduped: true });
  // another uploader, identical bytes: nothing stored, no id
  r = await reserve(h, f, TOKEN_OTHER);
  assertEquals(r.body, { uploadId: null, status: "complete", deduped: true });
  assertEquals(h.rows.length, 1);
});

// ── finalize ──

Deno.test("finalize: 409 not-uploaded until the object exists; 404 for a foreign or unknown id", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const { body } = await reserve(h, f);
  const id = body!.uploadId as string;
  assertEquals((await finalize(h, id)).body?.error, "not-uploaded");
  assertEquals((await finalize(h, id, TOKEN_OTHER)).res.status, 404);
  assertEquals((await finalize(h, "00000000-0000-4000-8000-999999999999")).res.status, 404);
  assertEquals((await finalize(h, "nope")).res.status, 400);
});

Deno.test("finalize: an object larger than announced, or over the cap, is refused and deleted", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const id = await reserveAndUpload(h, f, TOKEN, new Uint8Array(f.bytes.length + 1));
  let r = await finalize(h, id);
  assertEquals([r.res.status, r.body?.error], [409, "size-mismatch"]);
  assertEquals(h.objects.size, 0);
  assertEquals(h.rows[0].status, "pending");

  const g = await file(otherCache13());
  const id2 = await reserveAndUpload(h, g, TOKEN, new Uint8Array(4 * 1024 * 1024 + 1));
  r = await finalize(h, id2);
  assertEquals([r.res.status, r.body?.error], [413, "too-large"]);
  assertEquals(h.objects.size, 0);
});

Deno.test("finalize: bytes that do not hash to the announced sha256 are refused (409 hash-mismatch) and deleted", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const tampered = f.bytes.slice();
  tampered[tampered.length - 3] ^= 0x01;
  const id = await reserveAndUpload(h, f, TOKEN, tampered);
  const r = await finalize(h, id);
  assertEquals([r.res.status, r.body?.error], [409, "hash-mismatch"]);
  assertEquals(h.removed, [`${USER}/${f.sha}.cache`]);
  assertEquals(h.rows[0].status, "pending");
  assertEquals(h.completeCalls.length, 0);
  // a repeat reserve hands out a fresh URL; the correct file then finalizes
  const again = await reserve(h, f);
  assertEquals(again.body?.uploadId, id);
  assert(typeof again.body?.uploadUrl === "string");
  h.objects.set(again.body!.path as string, f.bytes);
  assertEquals((await finalize(h, id)).body?.status, "complete");
});

Deno.test("finalize: an unredacted cache is refused (422 invalid-cache / not-redacted) and deleted", async () => {
  const h = makeDeps();
  const f = await file(typicalCache(13, 0, false)); // the client announced the hash of what it really sends
  const id = await reserveAndUpload(h, f);
  const r = await finalize(h, id);
  assertEquals([r.res.status, r.body?.error, r.body?.reason], [422, "invalid-cache", "not-redacted"]);
  assertEquals(h.objects.size, 0);
  assertEquals(h.rows[0].status, "pending");
  assert(!JSON.stringify(r.body).includes("Synthetic Preset"));
});

Deno.test("finalize: header version != file name version, garbage and non-caches are 422 invalid-cache", async () => {
  const h = makeDeps();
  const cfg = { ...CFG, perFirmwareMax: 10 };
  const renamed = await file(typicalCache(12, 0, true)); // header 12.0 under a 13p0 name
  const garbage = await file(new Uint8Array(40000).fill(0x41));
  const truncated = await file(typicalCache().slice(0, typicalCache().length - 5));
  // structurally valid and redacted, but tiny: two of these must not be able to cover a firmware
  const tiny = await file(cache(13, 0, [section(40, [enumRec(0xffff, [blank("x")])])]), "effectDefinitions_11_13p0.cache");
  const expect: Array<[File, string]> = [
    [renamed, "version-mismatch"],
    [garbage, "header-version"],
    [truncated, "structure"],
    [tiny, "implausible"]
  ];
  for (const [f, reason] of expect) {
    const { body } = await reserve(h, f, TOKEN, {}, {}, cfg);
    h.objects.set(body!.path as string, f.bytes);
    const r = await finalize(h, body!.uploadId, TOKEN, cfg);
    assertEquals([r.res.status, r.body?.error, r.body?.reason], [422, "invalid-cache", reason], reason);
  }
  assertEquals(h.objects.size, 0);
});

Deno.test("finalize: complete with the server-read header version; idempotent; covered at 2 distinct uploaders", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const id = await reserveAndUpload(h, f, TOKEN_ANON);
  let r = await finalize(h, id, TOKEN_ANON);
  assertEquals(r.body, { uploadId: id, status: "complete", covered: false });
  assertEquals(h.completeCalls[0], { userId: ANON, rowId: id, bytes: f.bytes.length, contentVersion: "13.0", threshold: 2 });
  assertEquals(h.rows[0].contentVersion, "13.0");
  r = await finalize(h, id, TOKEN_ANON);
  assertEquals(r.body, { uploadId: id, status: "complete", covered: false });

  // the same uploader again (another file) does not make it covered
  const g = await file(otherCache13());
  const id2 = await reserveAndUpload(h, g, TOKEN_ANON);
  assertEquals((await finalize(h, id2, TOKEN_ANON)).body?.covered, false);

  // a second, distinct uploader does (with its own file: an identical one would only dedup)
  const k = await file(typicalCache(13, 0, true, { buildDate: "another unit" }));
  const id3 = await reserveAndUpload(h, k, TOKEN, undefined, { "x-real-ip": "198.51.100.30" });
  assertEquals((await finalize(h, id3)).body, { uploadId: id3, status: "complete", covered: true });

  // from now on the firmware is not wanted: status says so, a new reservation is refused
  const st = await call(h, req("GET", "?model=17&firmware=13.0", undefined, {}, null));
  assertEquals(st.body?.wanted, false);
  const late = await reserve(h, await file(typicalCache(13, 0, true, { buildDate: "late" })), TOKEN_OTHER);
  assertEquals([late.res.status, late.body?.error], [409, "not-wanted"]);
});

Deno.test("finalize: two anonymous ids on ONE network count once and cannot cover a firmware alone", async () => {
  const h = makeDeps();
  const a = await file(typicalCache());
  const b = await file(otherCache13());
  const idA = await reserveAndUpload(h, a, TOKEN_ANON);
  assertEquals((await finalize(h, idA, TOKEN_ANON)).body?.covered, false);
  const idB = await reserveAndUpload(h, b, TOKEN_ANON2); // same x-real-ip
  assertEquals((await finalize(h, idB, TOKEN_ANON2)).body?.covered, false);
  assertEquals(h.coverage.get("17/13.0")?.contributors, 1);
  // an uploader on another network does cover it
  const c = await file(typicalCache(13, 0, true, { buildDate: "third unit" }));
  const idC = await reserveAndUpload(h, c, TOKEN, undefined, { "x-real-ip": "198.51.100.77" });
  assertEquals((await finalize(h, idC)).body?.covered, true);
});

Deno.test("finalize: a file for another firmware than the device's is accepted but never covers", async () => {
  const h = makeDeps();
  const old12 = await file(typicalCache(12, 0, true), "effectDefinitions_11_12p0.cache", "12.0");
  const old12b = await file(typicalCache(12, 0, true, { buildDate: "b" }), "effectDefinitions_11_12p0.cache", "12.0");
  for (const [f, token] of [[old12, TOKEN], [old12b, TOKEN_OTHER]] as const) {
    const id = await reserveAndUpload(h, f, token);
    const r = await finalize(h, id, token);
    assertEquals(r.body?.covered, false);
  }
  assertEquals(h.coverage.size, 0);
  assertEquals((await call(h, req("GET", "?model=17&firmware=13.0", undefined, {}, null))).body?.wanted, true);
});

// ── delete + listing ──

Deno.test("delete: own upload — object first, then the row; foreign or unknown ids are 404", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const id = await reserveAndUpload(h, f, TOKEN_ANON);
  assertEquals((await finalize(h, id, TOKEN_ANON)).body?.status, "complete");
  assertEquals((await call(h, req("POST", "/delete", { uploadId: id }, {}, TOKEN))).res.status, 404);
  assertEquals((await call(h, req("POST", "/delete", { uploadId: "nope" }, {}, TOKEN_ANON))).res.status, 400);
  const ok = await call(h, req("POST", "/delete", { uploadId: id }, {}, TOKEN_ANON));
  assertEquals(ok.body, { uploadId: id, deleted: true });
  assertEquals(h.removed, [`${ANON}/${f.sha}.cache`]);
  assertEquals(h.rows.length, 0);
  assertEquals(h.objects.size, 0);
  // the network counter outlives the upload (no reset by delete + re-upload) and is unlinked from it
  assertEquals(h.ipUsage.length, 1);
  assertEquals(h.ipUsage[0].uploadId, null);
  assertEquals((await call(h, req("POST", "/delete", { uploadId: id }, {}, TOKEN_ANON))).res.status, 404);
});

Deno.test("delete: a storage failure keeps the row (retryable) and answers 500", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  const id = await reserveAndUpload(h, f);
  h.deps.removeObject = () => Promise.reject(new Error("storage down"));
  const r = await quiet(() => call(h, req("POST", "/delete", { uploadId: id })));
  assertEquals([r.res.status, r.body?.error], [500, "internal"]);
  assertEquals(h.rows.length, 1);
});

Deno.test("GET /mine lists the caller's own uploads only, never cached", async () => {
  const h = makeDeps();
  await reserveAndUpload(h, await file(typicalCache()), TOKEN_ANON);
  await reserveAndUpload(h, await file(otherCache13()), TOKEN);
  const r = await call(h, req("GET", "/mine", undefined, {}, TOKEN_ANON));
  assertEquals(r.res.status, 200);
  assertEquals(r.res.headers.get("cache-control"), "private, no-store");
  const list = r.body?.uploads as UploadSummary[];
  assertEquals(list.length, 1);
  assertEquals([list[0].model, list[0].deviceFirmware, list[0].status, list[0].versionMatch], [17, "13.0", "pending", true]);
  assertEquals((await call(h, req("GET", "?action=mine", undefined, {}, TOKEN))).body?.uploads instanceof Array, true);
});

Deno.test("a storage or database failure is a 500 without details", async () => {
  const h = makeDeps();
  const f = await file(typicalCache());
  h.deps.createUpload = () => Promise.reject(new Error("secret internal detail"));
  const r = await quiet(() => reserve(h, f));
  assertEquals(r.res.status, 500);
  assert(!JSON.stringify(r.body).includes("secret internal detail"));
});
