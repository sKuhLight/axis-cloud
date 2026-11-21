// Unit tests for the diagnostic-captures edge function (signed-upload flow). Run with:
//   deno test supabase/functions/diagnostic-captures/
// No Supabase stack or network is needed: handler.ts talks to the database and storage only through `Deps`,
// which these tests replace with in-memory fakes. What they therefore do NOT cover — and what needs a
// local-stack run — is everything behind that seam: the SQL function reserve_diagnostic_capture (atomic
// limits/dedup; see supabase/tests/database/diagnostic_captures.test.sql), the Supabase adapter in index.ts
// (storage duplicate/not-found detection, signed URLs, range read) and the bucket limits. The fake `reserve`
// below only mimics the SQL semantics so the handler's mapping of its outcomes can be asserted.
import { assert, assertEquals } from "jsr:@std/assert@1";
import {
  type CaptureRecord,
  DEFAULT_CONFIG,
  type Deps,
  type HandlerConfig,
  handleRequest,
  type ReserveArgs,
  type ReserveResult
} from "./handler.ts";
import { isGzip, objectPath, parseReserveRequest, readBodyCapped } from "./validate.ts";

const USER = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const ANON = "33333333-3333-4333-8333-333333333333";
const T0 = Date.parse("2026-11-21T12:00:00Z");

// ── fakes ──

interface Row extends CaptureRecord {
  userId: string;
  createdAt: number;
  firmware: string | null;
  model: number;
  state: string;
  app: Record<string, string>;
}

function gz(size: number): Uint8Array {
  const b = new Uint8Array(size);
  b[0] = 0x1f;
  b[1] = 0x8b;
  return b;
}

function makeDeps() {
  const rows: Row[] = [];
  const objects = new Map<string, Uint8Array>();
  const reserveCalls: ReserveArgs[] = [];
  const state = { now: T0, seq: 0 };

  const deps: Deps = {
    authenticate: (t) =>
      Promise.resolve(
        t === "good" ? { id: USER, isAnonymous: false } : t === "other" ? { id: OTHER, isAnonymous: false } : t === "anon" ? { id: ANON, isAnonymous: true } : null
      ),

    // Mimics reserve_diagnostic_capture: dedup, then rate limit, then byte quota, then insert.
    reserve: (a): Promise<ReserveResult> => {
      reserveCalls.push(a);
      const existing = rows.find((r) => r.userId === a.userId && r.captureId === a.captureId);
      if (existing) return Promise.resolve({ kind: "ok", id: existing.id, status: existing.status, deduped: true });
      const inWindow = rows.filter((r) => r.userId === a.userId && r.createdAt > state.now - a.windowSeconds * 1000).sort((x, y) => y.createdAt - x.createdAt);
      if (inWindow.length >= a.maxPerWindow) {
        const oldest = inWindow[a.maxPerWindow - 1].createdAt;
        return Promise.resolve({ kind: "limited", reason: "rate", retryAfterSeconds: Math.ceil((oldest + a.windowSeconds * 1000 - state.now) / 1000) });
      }
      const used = rows.filter((r) => r.userId === a.userId && r.createdAt > state.now - a.quotaWindowSeconds * 1000).reduce((s, r) => s + r.bytes, 0);
      if (used + a.bytes > a.quotaBytes) return Promise.resolve({ kind: "limited", reason: "quota", retryAfterSeconds: 4242 });
      const id = `00000000-0000-4000-8000-${String(++state.seq).padStart(12, "0")}`;
      rows.push({
        id,
        captureId: a.captureId,
        status: "pending",
        bytes: a.bytes,
        objectPath: objectPath(a.userId, a.captureId),
        userId: a.userId,
        createdAt: state.now,
        firmware: a.firmware,
        model: a.model,
        state: a.state,
        app: a.app
      });
      return Promise.resolve({ kind: "ok", id, status: "pending", deduped: false });
    },

    createUpload: (path) =>
      Promise.resolve(objects.has(path) ? "exists" : { uploadUrl: `https://storage.test/object/upload/sign/diagnostic-captures/${path}?token=T`, token: "T" }),

    getCapture: (u, id) => {
      const r = rows.find((x) => x.id === id && x.userId === u);
      return Promise.resolve(r ? { id: r.id, captureId: r.captureId, status: r.status, bytes: r.bytes, objectPath: r.objectPath } : null);
    },
    statObject: (p) => Promise.resolve(objects.has(p) ? { size: objects.get(p)!.length } : null),
    readHead: (p, n) => Promise.resolve(objects.has(p) ? objects.get(p)!.subarray(0, n) : null),
    completeCapture: (u, id, bytes) => {
      const r = rows.find((x) => x.id === id && x.userId === u && x.status === "pending");
      if (!r) return Promise.resolve(false);
      r.status = "complete";
      r.bytes = bytes;
      return Promise.resolve(true);
    }
  };
  return { deps, rows, objects, reserveCalls, state };
}

// ── request helpers ──

function post(suffix: string, body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(`http://localhost/diagnostic-captures${suffix}`, {
    method: "POST",
    headers: { authorization: "Bearer good", "content-type": "application/json", ...headers },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body)
  });
}

const reserveBody = (over: Record<string, unknown> = {}) => ({
  captureId: "cap-0001",
  model: 17,
  firmware: "12.0",
  app: { forgefx: "1.2.3", codec: "4.5.6", axis: "7.8.9", extra: "dropped" },
  state: "done",
  bytes: 1000,
  ...over
});

async function reserve(deps: Deps, over: Record<string, unknown> = {}, headers: Record<string, string> = {}, cfg?: HandlerConfig) {
  return await handleRequest(post("", reserveBody(over), headers), deps, cfg);
}

async function finalize(deps: Deps, captureId: unknown, headers: Record<string, string> = {}, suffix = "/finalize", cfg?: HandlerConfig) {
  return await handleRequest(post(suffix, { captureId }, headers), deps, cfg);
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

async function bodyOf(res: Response): Promise<Record<string, unknown>> {
  return await res.json();
}

/** Reserve `id`, then simulate the client's storage upload of `size` gzip bytes. Returns the row id. */
async function reserveAndUpload(h: ReturnType<typeof makeDeps>, id: string, size: number, announced = size): Promise<string> {
  const out = await bodyOf(await reserve(h.deps, { captureId: id, bytes: announced }));
  h.objects.set(objectPath(USER, id), gz(size));
  return out.captureId as string;
}

// ── protocol + auth ──

Deno.test("OPTIONS answers the CORS preflight and exposes Retry-After", async () => {
  const { deps } = makeDeps();
  const res = await handleRequest(new Request("http://localhost/x", { method: "OPTIONS" }), deps);
  assertEquals(res.status, 200);
  assert(res.headers.get("access-control-allow-headers")!.includes("authorization"));
  assertEquals(res.headers.get("access-control-expose-headers"), "Retry-After");
});

Deno.test("only POST is allowed", async () => {
  const { deps } = makeDeps();
  const res = await handleRequest(new Request("http://localhost/x", { method: "GET" }), deps);
  assertEquals(res.status, 405);
  assertEquals(res.headers.get("allow"), "POST, OPTIONS");
});

Deno.test("401 without a valid bearer token on both endpoints; nothing is reserved", async () => {
  const { deps, rows, reserveCalls } = makeDeps();
  for (const authorization of ["", "Bearer nope", "Basic abc"]) {
    for (const suffix of ["", "/finalize"]) {
      const res = await handleRequest(post(suffix, reserveBody(), { authorization }), deps);
      assertEquals(res.status, 401);
      assertEquals(await bodyOf(res), { error: "unauthorized" });
    }
  }
  assertEquals(rows.length, 0);
  assertEquals(reserveCalls.length, 0);
});

Deno.test("an anonymous session is refused (403) on both endpoints", async () => {
  const { deps, rows, reserveCalls } = makeDeps();
  const res = await reserve(deps, {}, { authorization: "Bearer anon" });
  assertEquals(res.status, 403);
  assertEquals((await bodyOf(res)).error, "account-required");
  assertEquals((await finalize(deps, "00000000-0000-4000-8000-000000000001", { authorization: "Bearer anon" })).status, 403);
  assertEquals(rows.length, 0);
  assertEquals(reserveCalls.length, 0);
});

Deno.test("an authentication outage is a 500, not a 401", async () => {
  const { deps } = makeDeps();
  deps.authenticate = () => Promise.reject(new Error("auth server unreachable"));
  assertEquals((await quiet(() => reserve(deps))).status, 500);
});

// ── reserve ──

Deno.test("reserve: pending row + signed upload for <user>/<capture>.json.gz", async () => {
  const { deps, rows, reserveCalls } = makeDeps();
  const res = await reserve(deps);
  assertEquals(res.status, 200);
  const out = await bodyOf(res);
  assertEquals(rows.length, 1);
  const path = `${USER}/cap-0001.json.gz`;
  assertEquals(out, {
    captureId: rows[0].id,
    status: "pending",
    uploadUrl: `https://storage.test/object/upload/sign/diagnostic-captures/${path}?token=T`,
    token: "T",
    path,
    bucket: "diagnostic-captures",
    expiresIn: 7200
  });
  const r = rows[0];
  assertEquals([r.userId, r.status, r.bytes, r.model, r.firmware, r.state], [USER, "pending", 1000, 17, "12.0", "done"]);
  assertEquals(r.app, { forgefx: "1.2.3", codec: "4.5.6", axis: "7.8.9" }); // unknown keys are not forwarded
  // The limits passed to the atomic reservation are the configured ones.
  assertEquals(reserveCalls[0], {
    userId: USER,
    captureId: "cap-0001",
    model: 17,
    firmware: "12.0",
    app: { forgefx: "1.2.3", codec: "4.5.6", axis: "7.8.9" },
    state: "done",
    bytes: 1000,
    maxPerWindow: 5,
    windowSeconds: 3600,
    quotaBytes: 200 * 1024 * 1024,
    quotaWindowSeconds: 30 * 24 * 3600
  });
});

Deno.test("reserve: firmware may be null/absent; an odd state does not reject", async () => {
  const { deps, rows } = makeDeps();
  assertEquals((await reserve(deps, { captureId: "a", firmware: null })).status, 200);
  assertEquals((await reserve(deps, { captureId: "b", firmware: undefined })).status, 200);
  assertEquals((await reserve(deps, { captureId: "c", state: "Weird State!" })).status, 200);
  assertEquals(rows.map((r) => r.firmware), [null, null, "12.0"]);
  assertEquals(rows[2].state, "unknown");
});

Deno.test("reserve: 400/413 for malformed requests; nothing is reserved", async () => {
  const { deps, rows } = makeDeps();
  const cases: Array<[string, Record<string, unknown>, number, string]> = [
    ["captureId missing", { captureId: undefined }, 400, "invalid-request"],
    ["captureId with path traversal", { captureId: "../../x" }, 400, "invalid-request"],
    ["captureId with slash", { captureId: "a/b" }, 400, "invalid-request"],
    ["captureId with a colon", { captureId: "2026-11-21T12:00:00Z" }, 400, "invalid-request"],
    ["model as string", { model: "17" }, 400, "invalid-request"],
    ["model out of range", { model: 999 }, 400, "invalid-request"],
    ["firmware a number", { firmware: 12 }, 400, "invalid-request"],
    ["bytes zero", { bytes: 0 }, 400, "invalid-request"],
    ["bytes a string", { bytes: "1000" }, 400, "invalid-request"],
    ["bytes fractional", { bytes: 1.5 }, 400, "invalid-request"],
    ["bytes above the limit", { bytes: 26214401 }, 413, "too-large"]
  ];
  for (const [name, over, status, error] of cases) {
    const res = await reserve(deps, over);
    assertEquals(res.status, status, name);
    assertEquals((await bodyOf(res)).error, error, name);
  }
  // bytes exactly at the limit is fine
  assertEquals((await reserve(deps, { captureId: "max", bytes: 26214400 })).status, 200);
  for (const [name, body, error] of [
    ["empty body", undefined, "empty-body"],
    ["not JSON", "not json {", "invalid-json"],
    ["JSON array", "[]", "invalid-request"]
  ] as Array<[string, string | undefined, string]>) {
    const res = await handleRequest(post("", body), deps);
    assertEquals(res.status, 400, name);
    assertEquals((await bodyOf(res)).error, error, name);
  }
  assertEquals(rows.length, 1); // only "max"
});

Deno.test("requests over the JSON body cap get 413 (declared length and streamed)", async () => {
  const { deps, reserveCalls } = makeDeps();
  // Declared Content-Length: replace the Request's guarded headers with a plain Headers object.
  const declared = post("", reserveBody());
  Object.defineProperty(declared, "headers", { value: new Headers({ authorization: "Bearer good", "content-length": "999999" }) });
  assertEquals(declared.headers.get("content-length"), "999999"); // the override took effect
  const res = await handleRequest(declared, deps);
  assertEquals(res.status, 413);
  assertEquals(await bodyOf(res), { error: "too-large", stage: "request", limit: 8192 });
  // No (usable) Content-Length: the streamed count enforces the cap.
  const streamed = await handleRequest(post("", "x".repeat(20_000)), deps);
  assertEquals(streamed.status, 413);
  assertEquals(reserveCalls.length, 0);
});

Deno.test("reserve: a repeat of a pending capture is deduped and gets a fresh upload URL (no second row)", async () => {
  const { deps, rows } = makeDeps();
  const first = await bodyOf(await reserve(deps));
  const again = await reserve(deps);
  assertEquals(again.status, 200);
  const out = await bodyOf(again);
  assertEquals(out.captureId, first.captureId);
  assertEquals(out.deduped, true);
  assertEquals(out.status, "pending");
  assert(typeof out.uploadUrl === "string" && typeof out.token === "string");
  assertEquals(rows.length, 1);
});

Deno.test("reserve: pending + object already uploaded -> no upload URL, finalize instead", async () => {
  const h = makeDeps();
  const rowId = await reserveAndUpload(h, "cap-0001", 1000);
  const res = await reserve(h.deps);
  assertEquals(res.status, 200);
  assertEquals(await bodyOf(res), { captureId: rowId, status: "pending", deduped: true });
});

Deno.test("reserve: a completed capture is deduped as complete", async () => {
  const h = makeDeps();
  const rowId = await reserveAndUpload(h, "cap-0001", 1000);
  assertEquals((await finalize(h.deps, rowId)).status, 200);
  const res = await reserve(h.deps);
  assertEquals(res.status, 200);
  assertEquals(await bodyOf(res), { captureId: rowId, deduped: true, status: "complete" });
});

Deno.test("reserve: rate limit maps to 429 with retryAfterSeconds + Retry-After; per user", async () => {
  const { deps, state, rows } = makeDeps();
  for (let i = 0; i < 5; i++) {
    state.now = T0 + i * 60_000; // one a minute
    assertEquals((await reserve(deps, { captureId: `cap-${i}` })).status, 200);
  }
  state.now = T0 + 5 * 60_000;
  const limited = await reserve(deps, { captureId: "cap-5" });
  assertEquals(limited.status, 429);
  const out = await bodyOf(limited);
  assertEquals(out.error, "rate-limited");
  assertEquals(out.limit, 5);
  assertEquals(out.windowSeconds, 3600);
  assertEquals(out.retryAfterSeconds, 55 * 60); // the oldest leaves the window at T0 + 60 min
  assertEquals(limited.headers.get("retry-after"), String(55 * 60));
  assertEquals(rows.length, 5);
  // Another user is not affected; a repeat of a known capture is never throttled.
  assertEquals((await reserve(deps, { captureId: "cap-5" }, { authorization: "Bearer other" })).status, 200);
  assertEquals((await reserve(deps, { captureId: "cap-4" })).status, 200);
  // After the oldest ages out, the slot frees up.
  state.now = T0 + 60 * 60_000 + 1000;
  assertEquals((await reserve(deps, { captureId: "cap-5" })).status, 200);
});

Deno.test("reserve: byte quota maps to 429 quota-exceeded", async () => {
  const { deps, rows } = makeDeps();
  const cfg: HandlerConfig = { ...DEFAULT_CONFIG, quotaBytes: 2500 };
  assertEquals((await reserve(deps, { captureId: "a", bytes: 1000 }, {}, cfg)).status, 200);
  assertEquals((await reserve(deps, { captureId: "b", bytes: 1000 }, {}, cfg)).status, 200);
  const res = await reserve(deps, { captureId: "c", bytes: 1000 }, {}, cfg);
  assertEquals(res.status, 429);
  assertEquals(await bodyOf(res), { error: "quota-exceeded", quotaBytes: 2500, windowSeconds: 30 * 24 * 3600, retryAfterSeconds: 4242 });
  assertEquals(res.headers.get("retry-after"), "4242");
  assertEquals(rows.length, 2);
});

Deno.test("reserve: failures in the reservation or the signed URL are a 500 without internals", async () => {
  const a = makeDeps();
  a.deps.reserve = () => Promise.reject(new Error("db down: secret detail"));
  const res = await quiet(() => reserve(a.deps));
  assertEquals(res.status, 500);
  const out = await bodyOf(res);
  assertEquals(out.error, "internal");
  assert(!JSON.stringify(out).includes("secret detail"));

  const b = makeDeps();
  b.deps.createUpload = () => Promise.reject(new Error("storage down"));
  assertEquals((await quiet(() => reserve(b.deps))).status, 500);
  // The row stays pending (a retry dedups and re-issues the URL; gc-blobs sweeps it otherwise).
  assertEquals(b.rows.length, 1);
});

// ── finalize ──

const ROW_UNKNOWN = "99999999-9999-4999-8999-999999999999";

Deno.test("finalize: validates the request", async () => {
  const { deps } = makeDeps();
  for (const captureId of [undefined, 42, "cap-0001", "not-a-uuid", "../x"]) {
    const res = await finalize(deps, captureId);
    assertEquals(res.status, 400, String(captureId));
    assertEquals((await bodyOf(res)).error, "invalid-request");
  }
  assertEquals((await handleRequest(post("/finalize", undefined), deps)).status, 400);
});

Deno.test("finalize: 404 for an unknown row and for another user's row", async () => {
  const h = makeDeps();
  const rowId = await reserveAndUpload(h, "cap-0001", 1000);
  assertEquals((await finalize(h.deps, ROW_UNKNOWN)).status, 404);
  assertEquals((await finalize(h.deps, rowId, { authorization: "Bearer other" })).status, 404);
  assertEquals(h.rows[0].status, "pending");
});

Deno.test("finalize: 409 until the object has been uploaded", async () => {
  const h = makeDeps();
  const out = await bodyOf(await reserve(h.deps));
  const res = await finalize(h.deps, out.captureId);
  assertEquals(res.status, 409);
  assertEquals((await bodyOf(res)).error, "not-uploaded");
  assertEquals(h.rows[0].status, "pending");
});

Deno.test("finalize: success flips the row to complete with the ACTUAL size; idempotent", async () => {
  const h = makeDeps();
  const rowId = await reserveAndUpload(h, "cap-0001", 900, 1000); // smaller than announced is fine
  const res = await finalize(h.deps, rowId);
  assertEquals(res.status, 200);
  assertEquals(await bodyOf(res), { captureId: rowId, status: "complete" });
  assertEquals([h.rows[0].status, h.rows[0].bytes], ["complete", 900]);
  // A repeat (client retry) is a 200 and changes nothing.
  assertEquals(await bodyOf(await finalize(h.deps, rowId)), { captureId: rowId, status: "complete" });
  assertEquals(h.rows[0].bytes, 900);
});

Deno.test("finalize: an object larger than announced is refused (size-mismatch) and left in place", async () => {
  const h = makeDeps();
  const rowId = await reserveAndUpload(h, "cap-0001", 5000, 1000);
  const res = await finalize(h.deps, rowId);
  assertEquals(res.status, 409);
  assertEquals(await bodyOf(res), { error: "size-mismatch", announced: 1000, actual: 5000 });
  assertEquals(h.rows[0].status, "pending");
  assert(h.objects.has(objectPath(USER, "cap-0001"))); // gc-blobs removes it with the pending row
});

Deno.test("finalize: an object above the hard limit is refused (413)", async () => {
  const h = makeDeps();
  const cfg: HandlerConfig = { ...DEFAULT_CONFIG, maxUploadBytes: 2000 };
  const out = await bodyOf(await reserve(h.deps, { bytes: 1000 }, {}, cfg));
  h.objects.set(objectPath(USER, "cap-0001"), gz(3000));
  const res = await finalize(h.deps, out.captureId, {}, "/finalize", cfg);
  assertEquals(res.status, 413);
  assertEquals(await bodyOf(res), { error: "too-large", stage: "stored", limit: 2000 });
});

Deno.test("finalize: a stored object that is not gzip is refused (400)", async () => {
  const notGzip = new TextEncoder().encode(JSON.stringify({ schema: 1 }));
  for (const bytes of [new Uint8Array([0x1f]), notGzip, new Uint8Array(500) /* zeros */]) {
    const h = makeDeps();
    const rowId = await reserveAndUpload(h, "cap-0001", 1000, 1000);
    h.objects.set(objectPath(USER, "cap-0001"), bytes);
    const res = await finalize(h.deps, rowId);
    assertEquals(res.status, 400);
    assertEquals((await bodyOf(res)).error, "invalid-gzip");
    assertEquals(h.rows[0].status, "pending");
  }
});

Deno.test("finalize: also routable as ?action=finalize and with a trailing slash", async () => {
  const h = makeDeps();
  const a = await reserveAndUpload(h, "cap-a", 100);
  const b = await reserveAndUpload(h, "cap-b", 100);
  assertEquals((await finalize(h.deps, a, {}, "?action=finalize")).status, 200);
  assertEquals((await finalize(h.deps, b, {}, "/finalize/")).status, 200);
  assertEquals(h.rows.map((r) => r.status), ["complete", "complete"]);
});

Deno.test("finalize: a concurrent finalize that already completed the row is a 200; a swept row is a 404", async () => {
  const h = makeDeps();
  const rowId = await reserveAndUpload(h, "cap-0001", 100);
  const real = h.deps.completeCapture;
  h.deps.completeCapture = (u, id, bytes) => {
    // The other request completes first, so this update finds no pending row.
    h.rows[0].status = "complete";
    return real(u, id, bytes);
  };
  assertEquals((await finalize(h.deps, rowId)).status, 200);

  const h2 = makeDeps();
  const row2 = await reserveAndUpload(h2, "cap-0001", 100);
  h2.deps.completeCapture = () => {
    h2.rows.length = 0; // gc-blobs removed the row in the meantime
    return Promise.resolve(false);
  };
  assertEquals((await finalize(h2.deps, row2)).status, 404);
});

Deno.test("finalize: a storage or database failure is a 500", async () => {
  const h = makeDeps();
  const rowId = await reserveAndUpload(h, "cap-0001", 100);
  h.deps.statObject = () => Promise.reject(new Error("storage down"));
  assertEquals((await quiet(() => finalize(h.deps, rowId))).status, 500);
});

Deno.test("end to end: reserve -> upload -> finalize -> repeat reserve", async () => {
  const h = makeDeps();
  const res = await bodyOf(await reserve(h.deps));
  h.objects.set(res.path as string, gz(1000));
  assertEquals((await finalize(h.deps, res.captureId)).status, 200);
  assertEquals(await bodyOf(await reserve(h.deps)), { captureId: res.captureId, deduped: true, status: "complete" });
  assertEquals(h.rows.length, 1);
});

// ── validate.ts ──

Deno.test("parseReserveRequest extracts and sanitizes the fields", () => {
  const r = parseReserveRequest(reserveBody());
  assert(r.ok);
  assertEquals(r.value, {
    captureId: "cap-0001",
    model: 17,
    firmware: "12.0",
    app: { forgefx: "1.2.3", codec: "4.5.6", axis: "7.8.9" },
    state: "done",
    bytes: 1000
  });
  const loose = parseReserveRequest(reserveBody({ app: "x", firmware: "  ", state: 5, model: 0 }));
  assert(loose.ok);
  assertEquals([loose.value.firmware, loose.value.app, loose.value.state, loose.value.model], [null, {}, "unknown", 0]);
});

Deno.test("readBodyCapped stops reading once the limit is exceeded", async () => {
  let pulled = 0;
  const stream = new ReadableStream<Uint8Array>({
    pull(c) {
      if (pulled >= 1000) return c.close();
      pulled++;
      c.enqueue(new Uint8Array(100));
    }
  });
  assertEquals(await readBodyCapped(stream, 1000), null);
  assert(pulled < 100, `kept reading after the cap (${pulled} chunks)`);
  assertEquals((await readBodyCapped(new Response(new Uint8Array(50)).body, 50))!.length, 50);
  assertEquals((await readBodyCapped(null, 50))!.length, 0);
});

Deno.test("isGzip checks the magic bytes", () => {
  assert(isGzip(gz(10)));
  assert(!isGzip(new Uint8Array([0x7b, 0x7d])));
  assert(!isGzip(new Uint8Array([0x1f])));
});
