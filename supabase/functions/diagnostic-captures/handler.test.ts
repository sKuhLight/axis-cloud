// Unit tests for the diagnostic-captures edge function. Run with:
//   deno test supabase/functions/diagnostic-captures/
// No Supabase stack or network is needed: handler.ts talks to storage/DB only through `UploadDeps`, which
// these tests replace with in-memory fakes. (The real Supabase adapter in index.ts is covered by the manual
// local-stack steps in the README.)
import { assert, assertEquals } from "jsr:@std/assert@1";
import { type CaptureRow, DEFAULT_CONFIG, handleUpload, type HandlerConfig, type UploadDeps } from "./handler.ts";
import { gunzipCapped, isGzip, objectPath, readBodyCapped, validateBundle } from "./bundle.ts";

const USER = "11111111-1111-4111-8111-111111111111";
const OTHER = "22222222-2222-4222-8222-222222222222";
const T0 = Date.parse("2026-11-21T12:00:00Z");

// ── helpers ──

async function gzip(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const body = new Response(bytes as BodyInit).body!.pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(body).arrayBuffer());
}

function bundle(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: 1,
    id: "cap-0001",
    createdAt: "2026-11-21T11:00:00.000Z",
    endedAt: "2026-11-21T11:05:00.000Z",
    state: "done",
    app: { forgefx: "1.2.3", codec: "4.5.6", axis: "7.8.9", extra: "dropped" },
    device: { model: 17, modelName: "FM3", firmware: "12.0", transport: "serial" },
    steps: [{ name: "info", status: "ok" }],
    frames: [{ t: 0, dir: "TX", hex: "f0 00 01 74 11 08 f7" }],
    logs: [],
    redaction: { presetNames: 0, dumpPayloadFrames: 0 },
    ...over
  };
}

interface StoredRow extends CaptureRow {
  id: string;
  created_at: string;
}

function makeDeps() {
  const rows: StoredRow[] = [];
  const objects = new Map<string, Uint8Array>();
  const removed: string[] = [];
  const state = { now: T0, seq: 0 };
  const deps: UploadDeps = {
    authenticate: (t) => Promise.resolve(t === "good" ? { id: USER } : t === "other" ? { id: OTHER } : null),
    findCapture: (u, c) => {
      const r = rows.find((x) => x.user_id === u && x.capture_id === c);
      return Promise.resolve(r ? { id: r.id } : null);
    },
    recentUploads: (u, since, limit) =>
      Promise.resolve(
        rows.filter((r) => r.user_id === u && r.created_at >= since).map((r) => r.created_at).sort().reverse().slice(0, limit)
      ),
    putObject: (p, b) => {
      if (objects.has(p)) return Promise.resolve("exists");
      objects.set(p, b);
      return Promise.resolve("created");
    },
    removeObject: (p) => {
      objects.delete(p);
      removed.push(p);
      return Promise.resolve();
    },
    insertCapture: (row) => {
      if (rows.some((x) => x.user_id === row.user_id && x.capture_id === row.capture_id)) return Promise.resolve("conflict");
      const id = `00000000-0000-4000-8000-${String(++state.seq).padStart(12, "0")}`;
      rows.push({ ...row, id, created_at: new Date(state.now).toISOString() });
      return Promise.resolve({ id });
    },
    now: () => state.now
  };
  return { deps, rows, objects, removed, state };
}

function post(body: Uint8Array | string | undefined, headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/diagnostic-captures", {
    method: "POST",
    headers: { authorization: "Bearer good", "content-type": "application/gzip", ...headers },
    body: body as BodyInit | undefined
  });
}

async function upload(deps: UploadDeps, b: Record<string, unknown>, headers: Record<string, string> = {}, cfg?: HandlerConfig) {
  return await handleUpload(post(await gzip(JSON.stringify(b)), headers), deps, cfg);
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

// ── handler: protocol ──

Deno.test("OPTIONS answers the CORS preflight", async () => {
  const { deps } = makeDeps();
  const res = await handleUpload(new Request("http://localhost/x", { method: "OPTIONS" }), deps);
  assertEquals(res.status, 200);
  assert(res.headers.get("access-control-allow-headers")!.includes("authorization"));
});

Deno.test("only POST is allowed", async () => {
  const { deps } = makeDeps();
  const res = await handleUpload(new Request("http://localhost/x", { method: "GET" }), deps);
  assertEquals(res.status, 405);
  assertEquals(res.headers.get("allow"), "POST, OPTIONS");
});

Deno.test("401 without a valid bearer token, and nothing is stored", async () => {
  const { deps, objects, rows } = makeDeps();
  const gz = await gzip(JSON.stringify(bundle()));
  for (const headers of [{ authorization: "" }, { authorization: "Bearer nope" }, { authorization: "Basic abc" }]) {
    const res = await handleUpload(post(gz, headers), deps);
    assertEquals(res.status, 401);
    assertEquals((await bodyOf(res)).error, "unauthorized");
  }
  assertEquals(objects.size, 0);
  assertEquals(rows.length, 0);
});

// ── handler: happy path + storage ──

Deno.test("stores the ORIGINAL gzip bytes at <user>/<capture>.json.gz and inserts the metadata row", async () => {
  const { deps, objects, rows } = makeDeps();
  const gz = await gzip(JSON.stringify(bundle()));
  const res = await handleUpload(post(gz), deps);
  assertEquals(res.status, 200);
  const out = await bodyOf(res);
  assertEquals(Object.keys(out), ["captureId"]);
  assertEquals(rows.length, 1);
  assertEquals(out.captureId, rows[0].id);

  const path = `${USER}/cap-0001.json.gz`;
  assertEquals(path, objectPath(USER, "cap-0001"));
  assertEquals(objects.get(path), gz); // byte-identical, not re-compressed
  const r = rows[0];
  assertEquals(r.user_id, USER);
  assertEquals(r.capture_id, "cap-0001");
  assertEquals(r.model, 17);
  assertEquals(r.firmware, "12.0");
  assertEquals(r.state, "done");
  assertEquals(r.bytes, gz.length);
  assertEquals(r.object_path, path);
  assertEquals(r.app, { forgefx: "1.2.3", codec: "4.5.6", axis: "7.8.9" }); // unknown keys are not stored
});

Deno.test("firmware may be null or absent", async () => {
  const { deps, rows } = makeDeps();
  assertEquals((await upload(deps, bundle({ id: "a", device: { model: 17, modelName: "FM3", firmware: null } }))).status, 200);
  assertEquals((await upload(deps, bundle({ id: "b", device: { model: 17, modelName: "FM3" } }))).status, 200);
  assertEquals(rows.map((r) => r.firmware), [null, null]);
});

Deno.test("an unexpected state string does not reject the bundle", async () => {
  const { deps, rows } = makeDeps();
  assertEquals((await upload(deps, bundle({ state: "Weird State!" }))).status, 200);
  assertEquals(rows[0].state, "unknown");
});

Deno.test("re-uploading the same capture id is idempotent (200, same id, one row, one object)", async () => {
  const { deps, rows, objects } = makeDeps();
  const first = await bodyOf(await upload(deps, bundle()));
  const second = await upload(deps, bundle());
  assertEquals(second.status, 200);
  const again = await bodyOf(second);
  assertEquals(again.captureId, first.captureId);
  assertEquals(again.deduped, true);
  assertEquals(rows.length, 1);
  assertEquals(objects.size, 1);
});

Deno.test("an unreferenced object at the path (earlier failed attempt) does not block the upload", async () => {
  const { deps, rows, objects, removed } = makeDeps();
  const path = objectPath(USER, "cap-0001");
  objects.set(path, new Uint8Array([1, 2, 3]));
  assertEquals((await upload(deps, bundle())).status, 200);
  assertEquals(rows.length, 1);
  assertEquals(objects.size, 1);
  assertEquals(removed, []);
});

Deno.test("a failing row insert removes the object this request created and answers 500", async () => {
  const { deps, objects, removed } = makeDeps();
  deps.insertCapture = () => Promise.reject(new Error("db down: secret detail"));
  const res = await quiet(() => upload(deps, bundle()));
  assertEquals(res.status, 500);
  const out = await bodyOf(res);
  assertEquals(out.error, "internal");
  assert(!JSON.stringify(out).includes("secret detail")); // internals stay in the log
  assertEquals(removed, [objectPath(USER, "cap-0001")]);
  assertEquals(objects.size, 0);
});

Deno.test("a failing insert does NOT remove an object that already existed", async () => {
  const { deps, objects, removed } = makeDeps();
  objects.set(objectPath(USER, "cap-0001"), new Uint8Array([9]));
  deps.insertCapture = () => Promise.reject(new Error("db down"));
  assertEquals((await quiet(() => upload(deps, bundle()))).status, 500);
  assertEquals(removed, []);
  assertEquals(objects.size, 1);
});

Deno.test("a concurrent identical upload that wins the insert race is answered with its row", async () => {
  const { deps, rows } = makeDeps();
  let calls = 0;
  const realFind = deps.findCapture;
  deps.findCapture = (u, c) => (calls++ === 0 ? Promise.resolve(null) : realFind(u, c));
  deps.insertCapture = (row) => {
    rows.push({ ...row, id: "winner-row", created_at: new Date(T0).toISOString() });
    return Promise.resolve("conflict");
  };
  const res = await upload(deps, bundle());
  assertEquals(res.status, 200);
  assertEquals(await bodyOf(res), { captureId: "winner-row", deduped: true });
});

Deno.test("an authentication outage is a 500, not a 401", async () => {
  const { deps } = makeDeps();
  deps.authenticate = () => Promise.reject(new Error("auth server unreachable"));
  assertEquals((await quiet(() => upload(deps, bundle()))).status, 500);
});

// ── handler: rate limit ──

Deno.test("5 new captures per rolling hour, then 429 with Retry-After; frees up later; per user", async () => {
  const { deps, state, rows } = makeDeps();
  for (let i = 0; i < 5; i++) {
    state.now = T0 + i * 60_000; // one a minute
    assertEquals((await upload(deps, bundle({ id: `cap-${i}` }))).status, 200);
  }
  state.now = T0 + 5 * 60_000;
  const limited = await upload(deps, bundle({ id: "cap-5" }));
  assertEquals(limited.status, 429);
  const out = await bodyOf(limited);
  assertEquals(out.error, "rate-limited");
  assertEquals(out.limit, 5);
  assertEquals(out.windowSeconds, 3600);
  // The oldest counted upload (T0) leaves the window at T0 + 60 min; now is T0 + 5 min -> 55 min.
  assertEquals(out.retryAfterSeconds, 55 * 60);
  assertEquals(limited.headers.get("retry-after"), String(55 * 60));
  assertEquals(rows.length, 5); // nothing stored for the rejected one

  // Another user is not affected.
  assertEquals((await upload(deps, bundle({ id: "cap-5" }), { authorization: "Bearer other" })).status, 200);

  // After the oldest ages out, the slot frees up.
  state.now = T0 + 60 * 60_000 + 1000;
  assertEquals((await upload(deps, bundle({ id: "cap-5" }))).status, 200);
});

Deno.test("an idempotent repeat is not throttled even when the user is at the limit", async () => {
  const { deps, state } = makeDeps();
  for (let i = 0; i < 5; i++) {
    state.now = T0 + i * 1000;
    assertEquals((await upload(deps, bundle({ id: `cap-${i}` }))).status, 200);
  }
  const repeat = await upload(deps, bundle({ id: "cap-4" }));
  assertEquals(repeat.status, 200);
  assertEquals((await bodyOf(repeat)).deduped, true);
});

// ── handler: size caps ──

Deno.test("413 when the compressed body exceeds the cap (streamed count, before gunzip)", async () => {
  const { deps, objects } = makeDeps();
  const cfg: HandlerConfig = { ...DEFAULT_CONFIG, maxCompressedBytes: 200 };
  const big = new Uint8Array(500).map((_, i) => (i * 7919) & 0xff); // not gzip; size check comes first
  const res = await handleUpload(post(big), deps, cfg);
  assertEquals(res.status, 413);
  assertEquals(await bodyOf(res), { error: "too-large", stage: "compressed", limit: 200 });
  assertEquals(objects.size, 0);
});

Deno.test("413 on a declared Content-Length above the cap", async () => {
  const { deps } = makeDeps();
  const cfg: HandlerConfig = { ...DEFAULT_CONFIG, maxCompressedBytes: 200 };
  const req = post(new Uint8Array(10), { "content-length": "999" });
  if (req.headers.get("content-length") !== "999") return; // this runtime drops the header on a Request
  const res = await handleUpload(req, deps, cfg);
  assertEquals(res.status, 413);
});

Deno.test("413 on a gzip bomb: decompressed output is capped", async () => {
  const { deps, objects } = makeDeps();
  const cfg: HandlerConfig = { ...DEFAULT_CONFIG, maxDecompressedBytes: 64 * 1024 };
  const bomb = await gzip(new Uint8Array(4 * 1024 * 1024)); // 4 MiB of zeros -> a few KB compressed
  assert(bomb.length < 64 * 1024);
  const res = await handleUpload(post(bomb), deps, cfg);
  assertEquals(res.status, 413);
  assertEquals(await bodyOf(res), { error: "too-large", stage: "decompressed", limit: 64 * 1024 });
  assertEquals(objects.size, 0);
});

// ── handler: malformed input (all 400, nothing stored) ──

Deno.test("400s for malformed bodies and bundles; nothing is stored", async () => {
  const { deps, objects, rows } = makeDeps();
  const good = await gzip(JSON.stringify(bundle()));
  // A truncated stream is reported as invalid-gzip or (runtime-dependent) as a cut-off JSON document.
  const cases: Array<[string, Uint8Array | undefined, string | string[]]> = [
    ["empty body", undefined, "empty-body"],
    ["plain JSON, not gzip", new TextEncoder().encode(JSON.stringify(bundle())), "invalid-gzip"],
    ["truncated gzip", good.subarray(0, good.length - 12), ["invalid-gzip", "invalid-json"]],
    ["gzip of non-JSON", await gzip("not json {"), "invalid-json"],
    ["gzip of invalid UTF-8", await gzip(new Uint8Array([0x7b, 0xff, 0xfe, 0x7d])), "invalid-json"],
    ["JSON array", await gzip("[]"), "invalid-bundle"],
    ["schema 2", await gzip(JSON.stringify(bundle({ schema: 2 }))), "invalid-bundle"],
    ["id missing", await gzip(JSON.stringify(bundle({ id: undefined }))), "invalid-bundle"],
    ["id with path traversal", await gzip(JSON.stringify(bundle({ id: "../../x" }))), "invalid-bundle"],
    ["id with slash", await gzip(JSON.stringify(bundle({ id: "a/b" }))), "invalid-bundle"],
    ["model as string", await gzip(JSON.stringify(bundle({ device: { model: "17", firmware: "12.0" } }))), "invalid-bundle"],
    ["model out of range", await gzip(JSON.stringify(bundle({ device: { model: 999, firmware: "12.0" } }))), "invalid-bundle"],
    ["firmware a number", await gzip(JSON.stringify(bundle({ device: { model: 17, firmware: 12 } }))), "invalid-bundle"],
    ["steps not an array", await gzip(JSON.stringify(bundle({ steps: {} }))), "invalid-bundle"]
  ];
  for (const [name, body, code] of cases) {
    const res = await handleUpload(post(body), deps);
    assertEquals(res.status, 400, name);
    const error = (await bodyOf(res)).error as string;
    assert(([] as string[]).concat(code).includes(error), `${name}: got ${error}`);
  }
  assertEquals(objects.size, 0);
  assertEquals(rows.length, 0);
});

// ── bundle.ts helpers ──

Deno.test("validateBundle extracts the metadata columns", () => {
  const r = validateBundle(bundle());
  assert(r.ok);
  assertEquals(r.meta, {
    captureId: "cap-0001",
    model: 17,
    firmware: "12.0",
    state: "done",
    app: { forgefx: "1.2.3", codec: "4.5.6", axis: "7.8.9" }
  });
  const loose = validateBundle(bundle({ app: "x", device: { model: 0, firmware: "  " } }));
  assert(loose.ok);
  assertEquals(loose.meta.firmware, null);
  assertEquals(loose.meta.app, {});
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

Deno.test("gunzipCapped round-trips, flags garbage and bombs", async () => {
  const text = "hello ".repeat(1000);
  const ok = await gunzipCapped(await gzip(text), 1 << 20);
  assert(ok.ok);
  assertEquals(new TextDecoder().decode(ok.data), text);
  assertEquals(await gunzipCapped(await gzip(text), 100), { ok: false, reason: "too-large" });
  const cut = await gunzipCapped(new Uint8Array([0x1f, 0x8b, 0, 0, 0, 0]), 1 << 20); // truncated header
  assert(!cut.ok || cut.data.length === 0);
  assert(isGzip(await gzip("x")));
  assert(!isGzip(new Uint8Array([0x7b, 0x7d])));
});
