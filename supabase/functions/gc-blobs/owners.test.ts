// Unit tests for gc-blobs/owners.ts (who still owns something, so the anonymous-user cleanup keeps them). Run with:
//   deno test supabase/functions/gc-blobs/
// The fake below behaves like the hosted Data API: it silently caps every answer at `maxRows` rows (ordered by an
// insertion id, as an unordered query would come back) but reports the exact count of all matching rows.
import { assertEquals, assertRejects } from "jsr:@std/assert@1";
import { type OwnerQuery, ownersAmong } from "./owners.ts";

type Rows = Record<string, string[]>; // table -> user_id per row

function fakeQuery(rows: Rows, maxRows: number, opts: { noCount?: boolean } = {}) {
  const calls: Array<[string, number]> = [];
  const query: OwnerQuery = (table, ids) => {
    calls.push([table, ids.length]);
    const set = new Set(ids);
    const all = (rows[table] ?? []).filter((u) => set.has(u));
    return Promise.resolve({ userIds: all.slice(0, maxRows), count: opts.noCount ? null : all.length });
  };
  return { query, calls };
}

const ids = (n: number, p = "u") => Array.from({ length: n }, (_, i) => `${p}${i}`);

Deno.test("an owner behind a heavy user is still found when the answer is truncated at max-rows", async () => {
  // u0 holds 1500 rows (more than one answer), u1 holds one row AFTER them, u2 nothing.
  const rows: Rows = { definition_source_contributions: [...new Array(1500).fill("u0"), "u1"] };
  const { query, calls } = fakeQuery(rows, 1000);
  const owners = await ownersAmong(["u0", "u1", "u2"], ["definition_source_contributions"], query);
  assertEquals([...owners].sort(), ["u0", "u1"]);
  // the naive single query would have returned 1000 × u0 only and treated u1 as owning nothing
  assertEquals(calls.length, 2);
});

Deno.test("owners across several tables and chunks", async () => {
  const rows: Rows = {
    editor_cache_uploads: ["a3", "a150"],
    diagnostic_captures: ["a3"],
    definition_source_contributions: ["a99", ...new Array(50).fill("a120")]
  };
  const { query } = fakeQuery(rows, 10);
  const owners = await ownersAmong(ids(200, "a"), ["editor_cache_uploads", "diagnostic_captures", "definition_source_contributions"], query);
  assertEquals([...owners].sort(), ["a120", "a150", "a3", "a99"]);
});

Deno.test("already settled owners are not asked again in later tables", async () => {
  const rows: Rows = { t1: ["x0", "x1"], t2: ["x0", "x1", "x2"] };
  const { query, calls } = fakeQuery(rows, 1000);
  const owners = await ownersAmong(["x0", "x1", "x2", "x3"], ["t1", "t2"], query);
  assertEquals([...owners].sort(), ["x0", "x1", "x2"]);
  assertEquals(calls, [["t1", 4], ["t2", 2]]);
});

Deno.test("fails closed when the backend reports no count or truncates without naming anyone new", async () => {
  await assertRejects(() => ownersAmong(["u0"], ["t"], fakeQuery({ t: ["u0"] }, 1000, { noCount: true }).query), Error, "no row count");
  const stuck: OwnerQuery = () => Promise.resolve({ userIds: [], count: 5 });
  await assertRejects(() => ownersAmong(["u0", "u1"], ["t"], stuck), Error, "without progress");
});

Deno.test("no ids, no queries", async () => {
  const { query, calls } = fakeQuery({}, 10);
  assertEquals((await ownersAmong([], ["t"], query)).size, 0);
  assertEquals(calls.length, 0);
});
