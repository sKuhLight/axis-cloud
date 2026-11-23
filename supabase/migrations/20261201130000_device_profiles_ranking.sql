-- v1 device-profile ranking (M4 WP-A3): the shared `device_profiles` store stops answering "the newest row".
--
-- WHY: `GET device-profiles` used to return the NEWEST row of a (model, firmware, schema), so a truncated live
-- walk uploaded AFTER a complete editor-cache profile displaced it for every client. Age says nothing about quality.
-- The function (supabase/functions/device-profiles) now ranks the candidates of one (model, firmware, schema) by
--   1. source: an `editor-cache` profile (byte-exact, parsed from the vendor's own definitions file) before a
--      `live-walk` one (read from the device; it can be cut short),
--   2. row_count, DESCENDING: the more (family, parameter id) entries a profile defines, the more complete it is,
--   3. created_at, ASCENDING: on a tie the OLDEST row stays (an equal newcomer never displaces an incumbent).
-- This migration adds what that order needs; the order itself lives in the function (PROFILE_ORDER, unit-tested) and
-- is only an ORDER BY over these columns.
--
-- row_count = the number of (family, parameter id) entries in `profile -> 'ranges'`
-- (`ranges` is `family -> parameter id -> range`). It is a catalog-free size measure: a walk that stopped early has
-- fewer entries than a complete one. It is deliberately NOT `profile.meta.recordCount` / `record_count`, which the
-- uploader supplies and which ranking must not trust.
--
-- A STORED GENERATED column, so that
--   * the database computes it from the stored document — no client can set it, and neither can the edge function
--     (an explicit value is rejected with 428C9; only DEFAULT is accepted) — and it can never drift from `profile`;
--   * existing rows are BACKFILLED by this very statement (every row is rewritten with its computed value);
--     the table holds a handful of profiles per model/firmware, so the rewrite is cheap;
--   * the v1 POST needs no change: it keeps inserting exactly the columns it inserted before.
-- Rows whose `ranges` is missing or not an object (the pgTAP fixtures insert `{}`) score 0.
--
-- No `if not exists` on the column or the index: a pre-existing `row_count` (a hand-made, NOT generated column) or a
-- `device_profiles_ranking_idx` with another definition would otherwise survive silently and the ranking would read
-- client-settable or unindexed data. Here the migration FAILS instead, and the maintainer looks.

-- The ALTER below takes an ACCESS EXCLUSIVE lock on device_profiles and rewrites the table (that is the backfill).
-- Waiting behind a long reader would queue every v1 GET behind this migration; give up after 5 s and retry instead.
-- Transaction-local (is_local = true), like SET LOCAL, but without SET LOCAL's 25P01 warning when the CLI runs the
-- file as one implicit transaction (a batch without BEGIN); the setting ends with this migration's transaction.
select set_config('lock_timeout', '5s', true);

-- Pure, so IMMUTABLE (a generated column demands it). `search_path = ''`: nothing here needs a schema; the jsonb
-- functions and operators are pg_catalog. A generated column's function is executed with the INSERTING role's
-- privileges (unlike a trigger function), hence the explicit grant below.
create or replace function public.device_profile_row_count(p_profile jsonb)
returns integer
language sql
immutable
parallel safe
set search_path = ''
as $$
  -- jsonb_each twice (families, then the ids of each family). Non-object values count 0 instead of raising, so a
  -- malformed historic row can never make the ALTER (or an insert) fail.
  select coalesce(sum((
           select count(*)
             from jsonb_each(case when jsonb_typeof(f.value) = 'object' then f.value else '{}'::jsonb end)
         )), 0)::integer
    from jsonb_each(
           case when jsonb_typeof(p_profile -> 'ranges') = 'object' then p_profile -> 'ranges' else '{}'::jsonb end
         ) as f
$$;

-- Not callable through the Data API: only the service role (the edge function's inserts evaluate the generated
-- column as that role) and the owner. Same hardening as every other helper in this schema.
revoke execute on function public.device_profile_row_count(jsonb) from public, anon, authenticated;
grant execute on function public.device_profile_row_count(jsonb) to service_role;

alter table public.device_profiles
  add column row_count integer not null
    generated always as (public.device_profile_row_count(profile)) stored;

-- The read path's only query shape, now: candidates of (model, firmware) ordered by the ranking above.
-- `source asc` puts 'editor-cache' first because it sorts before 'live-walk'; that is only sound while the
-- `source` check allows exactly those two values (device_profiles_ranking.test.sql pins both facts), so widen the
-- check and the order TOGETHER. `nulls last` mirrors the function's order terms (row_count is NOT NULL, so no
-- row is ever affected; it also makes the index serve the ORDER BY as written). The older
-- (model, firmware, created_at desc) index is left alone: dropping it is a separate, optional cleanup.
create index device_profiles_ranking_idx
  on public.device_profiles (model, firmware, source, row_count desc nulls last, created_at);

-- Public, non-sensitive, like the other public columns (explicit_grants.sql grants those per column; `created_by`
-- stays withheld). Reading a stored generated column evaluates nothing, so anon/authenticated need no EXECUTE.
-- service_role already holds table-level SELECT/INSERT. Writes need no grant work: the column is GENERATED, so
-- Postgres rejects any value written to it (428C9) whatever the grants say. (Projects created with the secure
-- defaults grant clients no INSERT/UPDATE here at all; older projects keep their implicit table-level INSERT/UPDATE
-- for anon/authenticated, which RLS — no write policy — already refuses. Neither can set row_count.)
grant select (row_count) on public.device_profiles to anon, authenticated;
