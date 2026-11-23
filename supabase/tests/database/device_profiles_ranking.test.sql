-- pgTAP tests for 20261201130000_device_profiles_ranking.sql: the v1 profile store ranks by source, then by a
-- server-computed row_count, then OLDEST first — never "newest wins".
--
-- What this covers (the function's own half — what it asks the database for, and the response shape — is
-- supabase/functions/device-profiles/handler.test.ts):
--   * row_count: a STORED GENERATED column over `profile -> 'ranges'` ((family, parameter id) entries), NOT NULL,
--     computed by the database, never from the uploader's meta.recordCount, tolerant of malformed documents;
--   * the BACKFILL: adding the column to a table that already holds rows (odd historic shapes included) fills
--     every row — rehearsed inside a rolled-back sub-transaction with the migration's own statement; likewise that a
--     pre-existing non-generated row_count or a same-named index makes the migration fail instead of surviving;
--   * the order, as the function asks for it (editor-cache first, row_count desc nulls last, created_at asc),
--     on candidate sets where a NEWER or BIGGER live walk sits next to an older editor-cache profile;
--   * the two facts that order relies on (editor-cache sorts before live-walk; the source check allows exactly
--     those two values) and the index that serves it;
--   * nobody can set row_count: the column is GENERATED, so Postgres rejects any value written to it regardless of
--     grants (older projects keep table-level INSERT/UPDATE for anon/authenticated, new-default ones grant none;
--     either way the client writes below fail, and not even the service role or the owner can store a value).
-- Privileges of the new column and helper are asserted in explicit_grants.test.sql.
--
-- Run against a LOCAL stack only (it needs the migrations applied and creates throw-away rows inside a
-- transaction that is rolled back):
--   npx --yes supabase@latest start
--   npx --yes supabase@latest db reset
--   npx --yes supabase@latest test db
begin;
create extension if not exists pgtap with schema extensions;

select plan(46);

-- ── helpers (temp, owner only) ──

-- a profile with `p_fams` families of `p_ids` parameter ranges each: (family, id) entries = p_fams * p_ids
create function pg_temp.prof(p_fams integer, p_ids integer, p_rec integer default 0) returns jsonb
language sql as $$
  select jsonb_build_object(
    'ranges', (select jsonb_object_agg('f' || f,
                 (select jsonb_object_agg(i::text, jsonb_build_object('kind', 'float', 'min', 0, 'max', 1))
                    from generate_series(1, p_ids) as i))
                 from generate_series(1, p_fams) as f),
    'meta', jsonb_build_object('recordCount', p_rec));
$$;

-- the ranking exactly as device-profiles/handler.ts PROFILE_ORDER asks for it (PostgREST
-- order=source.asc.nullslast,row_count.desc.nullslast,created_at.asc.nullslast), best row's content_hash
create function pg_temp.best(p_model integer, p_firmware text) returns text
language sql as $$
  select content_hash
    from public.device_profiles
   where model = p_model and firmware = p_firmware
   order by source asc, row_count desc nulls last, created_at asc
   limit 1
$$;

-- ── the column and what serves it (5) ──
select is(
  (select attgenerated::text from pg_attribute where attrelid = 'public.device_profiles'::regclass and attname = 'row_count' and not attisdropped),
  's', 'row_count is a STORED generated column (computed by the database)');
select is(
  (select attnotnull from pg_attribute where attrelid = 'public.device_profiles'::regclass and attname = 'row_count' and not attisdropped),
  true, 'row_count is NOT NULL');
select is(
  (select format_type(atttypid, atttypmod) from pg_attribute where attrelid = 'public.device_profiles'::regclass and attname = 'row_count' and not attisdropped),
  'integer', 'row_count is an integer');
select ok(
  exists (select 1 from pg_indexes
           where schemaname = 'public' and tablename = 'device_profiles' and indexname = 'device_profiles_ranking_idx'
             and indexdef like '%(model, firmware, source, row_count DESC NULLS LAST, created_at)'),
  'the ranking index covers (model, firmware, source, row_count desc nulls last, created_at)');
select ok(
  (select provolatile = 'i' and exists (select 1 from unnest(proconfig) as c where c like 'search_path=%')
     from pg_proc where oid = 'public.device_profile_row_count(jsonb)'::regprocedure),
  'device_profile_row_count is immutable and has a pinned search_path');

-- ── the two facts the `source asc` term relies on (2) ──
select is('editor-cache'::text < 'live-walk'::text, true, 'editor-cache sorts before live-walk (so source ASC ranks it first)');
select throws_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source)
    values (18, '98.0', 'rk-bad-source', '{}'::jsonb, 'manual')$$,
  '23514', null, 'the source check allows only editor-cache and live-walk: widen it and the order together');

-- ── what row_count counts: (family, parameter id) entries of profile.ranges (9) ──
select is(public.device_profile_row_count('{"ranges":{"a":{"1":{},"2":{}},"b":{"7":{}}}}'::jsonb), 3, 'counts the ids of every family');
select is(public.device_profile_row_count(pg_temp.prof(4, 5)), 20, 'counts families x ids');
select is(public.device_profile_row_count('{}'::jsonb), 0, 'no ranges: 0');
select is(public.device_profile_row_count('{"ranges":{}}'::jsonb), 0, 'empty ranges: 0');
select is(public.device_profile_row_count('{"ranges":[1,2,3]}'::jsonb), 0, 'ranges that is not an object: 0, no error');
select is(public.device_profile_row_count('{"ranges":{"a":7,"b":{"1":{},"2":{}},"c":[1,2],"d":{}}}'::jsonb), 2, 'a family that is not an object counts 0, no error');
select is(public.device_profile_row_count('null'::jsonb), 0, 'a JSON null profile: 0');
select is(public.device_profile_row_count(null), 0, 'a NULL profile: 0');
select is(public.device_profile_row_count('{"ranges":{"a":{"1":{}}},"meta":{"recordCount":99999},"record_count":99999}'::jsonb), 1,
  'the uploader''s recordCount does not count');

-- ── the column on real rows (6) ──
insert into public.device_profiles (model, firmware, content_hash, profile, source, record_count)
  values (18, '90.0', 'rc-1', pg_temp.prof(4, 5, 7), 'editor-cache', 7);
select is((select row_count from public.device_profiles where content_hash = 'rc-1'), 20, 'an insert gets the computed row_count');
insert into public.device_profiles (model, firmware, content_hash, profile, source, record_count)
  values (18, '90.0', 'rc-2', pg_temp.prof(1, 1, 100000), 'live-walk', 100000);
select is((select row_count from public.device_profiles where content_hash = 'rc-2'), 1, 'a huge uploader-supplied recordCount does not raise it');
update public.device_profiles set profile = pg_temp.prof(2, 2) where content_hash = 'rc-1';
select is((select row_count from public.device_profiles where content_hash = 'rc-1'), 4, 'an update of the profile recomputes it');
select throws_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source, row_count)
    values (18, '90.1', 'rc-3', '{}'::jsonb, 'live-walk', 1000000)$$,
  '428C9', null, 'the owner cannot insert a row_count of its own');
select throws_ok(
  $$update public.device_profiles set row_count = 1000000 where content_hash = 'rc-1'$$,
  '428C9', null, 'the owner cannot update row_count');
select is((select row_count from public.device_profiles where content_hash = 'rc-1'), 4, 'row_count is unchanged by the refused writes');

-- ── the backfill: adding the column to a table that already holds rows (2) ──
-- Rehearsed with the migration's own statement inside a sub-transaction that is rolled back (DDL is
-- transactional): drop the column (and with it its index and grant), insert rows the way they existed before the
-- column did - complete profiles, junk, odd shapes - add it again, read the result.
create function pg_temp.rehearse_backfill() returns text
language plpgsql as $f$
declare
  v text;
begin
  begin
    alter table public.device_profiles drop column row_count;
    insert into public.device_profiles (model, firmware, content_hash, profile, source) values
      (19, '1.0', 'bf-1', pg_temp.prof(3, 4), 'editor-cache'),
      (19, '1.0', 'bf-2', '{}'::jsonb, 'live-walk'),
      (19, '1.0', 'bf-3', '{"ranges":[1,2,3]}'::jsonb, 'live-walk'),
      (19, '1.0', 'bf-4', '{"ranges":{"a":7,"b":{"1":{},"2":{}}}}'::jsonb, 'live-walk'),
      (19, '1.0', 'bf-5', '{"ranges":{"a":{"1":{}}},"meta":{"recordCount":99999}}'::jsonb, 'live-walk');
    -- the migration's statement
    alter table public.device_profiles
      add column row_count integer not null
        generated always as (public.device_profile_row_count(profile)) stored;
    select string_agg(content_hash || '=' || row_count, ',' order by content_hash) into v
      from public.device_profiles where model = 19;
    raise exception using errcode = 'XB001', message = v;
  exception when sqlstate 'XB001' then
    return sqlerrm;
  end;
end
$f$;
select is(pg_temp.rehearse_backfill(), 'bf-1=12,bf-2=0,bf-3=0,bf-4=2,bf-5=1',
  'adding the column fills every existing row, malformed ones included, and the NOT NULL holds');
select is((select row_count from public.device_profiles where content_hash = 'rc-2'), 1, 'the rehearsal was rolled back: the column and its rows are as before');

-- ── no silent survivors: a hand-made row_count or a clashing index makes the migration FAIL (2) ──
-- The migration has no `if not exists`: a pre-existing NOT generated row_count (client-settable) or another index of
-- the same name must stop it rather than be kept. Rehearsed like the backfill, in rolled-back sub-transactions.
create function pg_temp.rehearse_column_clash() returns text
language plpgsql as $f$
begin
  begin
    alter table public.device_profiles drop column row_count;
    alter table public.device_profiles add column row_count integer;   -- hand-made, NOT generated
    -- the migration's statement
    alter table public.device_profiles
      add column row_count integer not null
        generated always as (public.device_profile_row_count(profile)) stored;
    raise exception using errcode = 'XB002', message = 'the statement kept the hand-made column';
  exception
    when duplicate_column then return 'duplicate_column';
    when sqlstate 'XB002' then return sqlerrm;
  end;
end
$f$;
select is(pg_temp.rehearse_column_clash(), 'duplicate_column', 'a pre-existing non-generated row_count makes the migration fail');
create function pg_temp.rehearse_index_clash() returns text
language plpgsql as $f$
begin
  begin
    drop index public.device_profiles_ranking_idx;
    create index device_profiles_ranking_idx on public.device_profiles (model);   -- same name, other definition
    -- the migration's statement
    create index device_profiles_ranking_idx
      on public.device_profiles (model, firmware, source, row_count desc nulls last, created_at);
    raise exception using errcode = 'XB003', message = 'the statement kept the other index';
  exception
    when duplicate_table then return 'duplicate_table';
    when sqlstate 'XB003' then return sqlerrm;
  end;
end
$f$;
select is(pg_temp.rehearse_index_clash(), 'duplicate_table', 'an index of the same name with another definition makes the migration fail');

-- ── the ranking: editor-cache first, then MORE ranges, then OLDEST (13) ──
-- 99.0: an older complete editor-cache profile against a NEWER and BIGGER live walk (the reported failure)
insert into public.device_profiles (model, firmware, content_hash, profile, source, created_at) values
  (18, '99.0', 'ed-old-small', pg_temp.prof(2, 3), 'editor-cache', '2026-11-01 00:00:00+00'),   -- 6
  (18, '99.0', 'live-new-big',  pg_temp.prof(9, 9), 'live-walk',    '2026-11-20 00:00:00+00');  -- 81
select is(pg_temp.best(18, '99.0'), 'ed-old-small', 'a newer, bigger live walk does not displace the older editor-cache profile');
insert into public.device_profiles (model, firmware, content_hash, profile, source, created_at) values
  (18, '99.0', 'ed-new-big', pg_temp.prof(4, 10), 'editor-cache', '2026-11-25 00:00:00+00');   -- 40
select is(pg_temp.best(18, '99.0'), 'ed-new-big', 'among editor-cache profiles the one with more ranges wins, although it is newer');
delete from public.device_profiles where content_hash in ('ed-old-small', 'ed-new-big');
select is(pg_temp.best(18, '99.0'), 'live-new-big', 'without an editor-cache profile the live walk is served');

-- 99.1: equal source and row_count -> OLDEST; a live walk (older, with more ranges) still loses to editor-cache
insert into public.device_profiles (model, firmware, content_hash, profile, source, created_at) values
  (18, '99.1', 'tie-mid',    pg_temp.prof(2, 3), 'editor-cache', '2026-11-15 00:00:00+00'),
  (18, '99.1', 'tie-oldest', pg_temp.prof(3, 2), 'editor-cache', '2026-11-01 00:00:00+00'),
  (18, '99.1', 'tie-newest', pg_temp.prof(1, 6), 'editor-cache', '2026-11-30 00:00:00+00'),
  (18, '99.1', 'live-older-bigger', pg_temp.prof(10, 10), 'live-walk', '2026-10-01 00:00:00+00');
select is(
  (select array_agg(row_count order by content_hash) from public.device_profiles where firmware = '99.1' and source = 'editor-cache'),
  array[6, 6, 6], 'the three editor-cache profiles have the same row_count');
select is(pg_temp.best(18, '99.1'), 'tie-oldest', 'on a tie the OLDEST row stays; an older live walk with more ranges does not matter');
delete from public.device_profiles where content_hash = 'tie-oldest';
select is(pg_temp.best(18, '99.1'), 'tie-mid', 'the next oldest follows');

-- 99.2: live walks only: more ranges first, oldest on a tie
insert into public.device_profiles (model, firmware, content_hash, profile, source, created_at) values
  (18, '99.2', 'live-a', pg_temp.prof(2, 3), 'live-walk', '2026-11-01 00:00:00+00'),    -- 6
  (18, '99.2', 'live-b', pg_temp.prof(3, 2), 'live-walk', '2026-11-25 00:00:00+00'),    -- 6
  (18, '99.2', 'live-c', pg_temp.prof(5, 6), 'live-walk', '2026-11-10 00:00:00+00');    -- 30
select is(pg_temp.best(18, '99.2'), 'live-c', 'live walks: the one with the most ranges wins, not the newest');
delete from public.device_profiles where content_hash = 'live-c';
select is(pg_temp.best(18, '99.2'), 'live-a', 'live walks with equal ranges: the oldest stays');

-- a truncated live walk uploaded LATER never displaces: the order the function used before would pick the newest
select is((select content_hash from public.device_profiles where firmware = '99.1' order by created_at desc limit 1), 'tie-newest',
  'sanity: the old order (created_at desc) would have served the newest row');
select isnt(pg_temp.best(18, '99.1'), 'tie-newest', 'and the ranking does not');

-- the order is per (model, firmware): other firmwares and models are not candidates
select is(pg_temp.best(18, '99.9'), null::text, 'no row for an unknown firmware');
select is(pg_temp.best(17, '99.2'), null::text, 'no row for another model');
select is(pg_temp.best(18, '99.2'), 'live-a', 'the candidates are those of the asked (model, firmware) only');

-- ── nobody but the database sets row_count (7) ──
-- 428C9 for every role: the rewriter refuses a value for a generated column before any privilege or RLS check, so
-- these hold on old and new-default projects alike. (That clients cannot insert device_profiles rows AT ALL is
-- explicit_grants.test.sql's business.)
set local role anon;
set local request.jwt.claims = '{"role":"anon"}';
select throws_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source, row_count)
    values (18, '97.0', 'cl-anon', '{}'::jsonb, 'live-walk', 1000000)$$,
  '428C9', null, 'anon cannot insert a row_count of its own');
select throws_ok($$update public.device_profiles set row_count = 1000000$$, '428C9', null, 'anon cannot update row_count');
reset role;

set local role authenticated;
set local request.jwt.claims = '{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated"}';
select throws_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source, row_count)
    values (18, '97.0', 'cl-auth', '{}'::jsonb, 'live-walk', 1000000)$$,
  '428C9', null, 'authenticated cannot insert a row_count of its own');
select throws_ok($$update public.device_profiles set row_count = 1000000$$, '428C9', null, 'authenticated cannot update row_count');
reset role;

set local role service_role;
select throws_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source, row_count)
    values (18, '97.0', 'cl-svc', '{"ranges":{"a":{"1":{}}}}'::jsonb, 'live-walk', 1000000)$$,
  '428C9', null, 'the service role (the edge function) cannot store a row_count of its own either');
select lives_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source)
    values (18, '97.0', 'cl-svc-ok', '{"ranges":{"a":{"1":{},"2":{}}}}'::jsonb, 'live-walk')$$,
  'the service role inserts as before - the database computes row_count');
reset role;
select is((select row_count from public.device_profiles where content_hash = 'cl-svc-ok'), 2, 'and it is computed from the stored profile');

select * from finish();
rollback;
