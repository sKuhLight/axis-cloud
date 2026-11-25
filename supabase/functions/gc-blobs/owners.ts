// Which users still OWN something (gc-blobs' anonymous-user cleanup must never delete those). Pure — the database
// access is the `OwnerQuery` the caller passes in — so owners.test.ts runs without a Supabase stack.
//
// Why this is not one `select user_id … in (ids)`: the hosted Data API caps every answer at its max-rows setting
// (1000 by default) WITHOUT an error. A chunk of 100 users of whom one holds 1000+ rows would come back truncated,
// the remaining owners would look like owning nothing, and the cleanup would delete them (and, by cascade, their
// uploads or shared-definition votes). So every query also asks for the exact row count: an answer shorter than its
// count is incomplete, the users it did name are settled, and the rest are asked again. Anything that cannot be
// settled (no count, no progress) throws — the caller then deletes nobody (fail closed).

/** The `user_id` values of the rows of `table` whose user_id is in `ids` (possibly truncated) and the exact number
 *  of such rows (`null` when the backend did not report one). */
export type OwnerQuery = (table: string, ids: readonly string[]) => Promise<{ userIds: string[]; count: number | null }>;

/** Ids among `ids` that own at least one row in any of `tables`, asking at most `chunkSize` ids per query. */
export async function ownersAmong(ids: readonly string[], tables: readonly string[], query: OwnerQuery, chunkSize = 100): Promise<Set<string>> {
  const owning = new Set<string>();
  for (let i = 0; i < ids.length; i += chunkSize) {
    const chunk = ids.slice(i, i + chunkSize);
    for (const table of tables) {
      let pending = chunk.filter((id) => !owning.has(id));
      while (pending.length > 0) {
        const { userIds, count } = await query(table, pending);
        if (count === null || !Number.isFinite(count)) throw new Error(`owners: ${table} gave no row count`);
        const asked = new Set(pending);
        for (const id of userIds) if (asked.has(id)) owning.add(id);
        if (userIds.length >= count) break; // complete answer
        const next = pending.filter((id) => !owning.has(id));
        // A truncated answer names at least one pending owner; if it named none, the rest cannot be settled.
        if (next.length === pending.length) throw new Error(`owners: ${table} answer truncated without progress`);
        pending = next;
      }
    }
  }
  return owning;
}
