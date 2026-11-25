-- pgTAP tests for the shared device definitions store (20261201120000_definition_sources.sql): privileges and RLS
-- (public column-level read of definition_sources with day-granular dates only, rejected/quarantined/orphaned rows
-- invisible, private tables closed, no EXECUTE for clients), constraints (canonical firmware, pinned tiers, the
-- shared-source privacy backstop, report consistency), the ranking (per kind, never across kinds; tier -> quality
-- -> coverage -> contributors -> networks -> oldest), contribute (dedupe by fact hash, verified only at quality 3
-- with 2 users x 2 networks, a cleaner live confirmation raising the quality, one vote per uploader and kind,
-- rejected facts refused, the limits XQ001/XQ002/XQ005/XQ006 with retry seconds, the withdraw/re-share residual),
-- withdraw and direct deletes (counters recomputed, orphans deleted, pinned kept), reports (high-water counters,
-- contributors' own reports not counted, quarantine rule, verified never quarantined), the 180-day unlink, the
-- account deletion cascade + orphan cleanup, and (20261201121000_definition_sources_orphan_reset.sql) the reset of
-- an orphan an identical share meets.
--
-- All data is synthetic (no device data). Run against a LOCAL stack only (it needs the migrations applied and
-- creates throw-away users inside a transaction that is rolled back):
--   npx --yes supabase@latest start
--   npx --yes supabase@latest db reset
--   npx --yes supabase@latest test db
-- NB: now() is constant inside the transaction, so every row created here has the same timestamps; tests that need
-- age set them explicitly. Statements run as a client role (anon / authenticated) use literals only: the pg_temp
-- helpers below are for the table owner.
begin;
create extension if not exists pgtap with schema extensions;

select plan(212);

-- ── helpers (session-local) ──
create function pg_temp.u(i integer) returns uuid language sql immutable
  as $$ select ('d0000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid $$;
-- distinct 64-hex values per number (keyed network hash / fact hash stand-ins)
create function pg_temp.net(i integer) returns text language sql immutable
  as $$ select encode(sha256(convert_to('network-' || i, 'UTF8')), 'hex') $$;
create function pg_temp.fh(i integer) returns text language sql immutable
  as $$ select encode(sha256(convert_to('facts-' || i, 'UTF8')), 'hex') $$;
-- a minimal synthetic source of the shared shape
create function pg_temp.src(p_kind text, p_fw text) returns jsonb language sql immutable
  as $$ select jsonb_build_object('kind', p_kind, 'firmware', p_fw, 'codecVersion', '0.0.0-test', 'records', '[]'::jsonb) $$;
-- a source row written directly (ranking, RLS and constraint tests)
create function pg_temp.put(
  p_kind         text,
  p_fw           text,
  p_fact         integer,
  p_quality      integer     default 3,
  p_coverage     integer     default 100,
  p_contributors integer     default 1,
  p_networks     integer     default 1,
  p_first_seen   timestamptz default now(),
  p_tier         text        default 'candidate',
  p_pinned       boolean     default false,
  p_failures     integer     default 0,
  p_passes       integer     default 0,
  p_raw_format   integer     default 1,
  p_model        integer     default 17,
  p_source       jsonb       default null,
  p_summary      jsonb       default '{}'::jsonb,
  p_fact_hash    text        default null,
  p_bytes        integer     default 1000
) returns uuid language sql as $$
  insert into public.definition_sources
    (model, firmware, kind, raw_format, fact_hash, source, summary, quality, coverage_score, bytes, tier, pinned,
     contributors, networks, spot_passes, spot_failures, first_seen)
  values
    (p_model, p_fw, p_kind, p_raw_format, coalesce(p_fact_hash, pg_temp.fh(p_fact)), coalesce(p_source, pg_temp.src(p_kind, p_fw)),
     p_summary, p_quality, p_coverage, p_bytes, p_tier, p_pinned, p_contributors, p_networks, p_passes, p_failures, p_first_seen)
  returning id
$$;
create function pg_temp.sid(p_fact integer, p_kind text default 'editor-cache', p_fw text default '13.0') returns uuid
  language sql stable
  as $$ select id from public.definition_sources where model = 17 and firmware = p_fw and kind = p_kind and fact_hash = pg_temp.fh(p_fact) $$;
-- contribute as uploader p_user from network p_net
create function pg_temp.share(
  p_user     integer,
  p_net      integer,
  p_fact     integer,
  p_kind     text    default 'editor-cache',
  p_fw       text    default '13.0',
  p_quality  integer default 3,
  p_bytes    integer default 1000,
  p_max      integer default 10,
  p_netmax   integer default 10,
  p_quota    bigint  default 41943040,
  p_netquota bigint  default 41943040
) returns table (source_id uuid, created boolean, deduped boolean, confirmed boolean, tier text, contributors integer, networks integer)
language sql as $$
  select * from public.contribute_definition_source(
    pg_temp.u(p_user), pg_temp.net(p_net), 17, p_fw, p_kind, 1, pg_temp.fh(p_fact), pg_temp.src(p_kind, p_fw),
    '{}'::jsonb, p_quality, 100, p_bytes, '{"forgefx":"0.0.0-test"}'::jsonb, now(), 1,
    p_max_per_window => p_max, p_net_max_per_window => p_netmax, p_quota_bytes => p_quota, p_net_quota_bytes => p_netquota)
$$;
create function pg_temp.wd(p_user integer, p_source uuid default null, p_model integer default null, p_fw text default null)
  returns text language sql
  as $$ select concat_ws('/', withdrawn, deleted_sources) from public.withdraw_definition_contributions(pg_temp.u(p_user), p_source, p_model, p_fw) $$;
-- a spot-check report (failed = 1 mismatch of 24, passed = 24/24)
create function pg_temp.rep(p_user integer, p_net integer, p_source uuid, p_verdict text, p_max integer default 30, p_netmax integer default 30)
  returns boolean language sql
  as $$ select quarantined from public.report_definition_source(
          pg_temp.u(p_user), pg_temp.net(p_net), p_source, p_verdict, 24,
          case when p_verdict = 'failed' then 23 else 24 end, case when p_verdict = 'failed' then 1 else 0 end,
          '{}'::jsonb, p_max_per_window => p_max, p_net_max_per_window => p_netmax) $$;
-- the DETAIL of the error a statement raises (limit errors carry the retry seconds there)
create function pg_temp.detail_of(q text) returns text language plpgsql as $$
declare d text;
begin
  execute q;
  return null;
exception when others then
  get stacked diagnostics d = pg_exception_detail;
  return d;
end $$;

insert into auth.users (id, email)
  select pg_temp.u(g), 'defsrc-' || g || '@example.test' from generate_series(1, 70) g;

-- ═════════════════════════════ A. privileges and RLS (43) ═════════════════════════════

-- the six service functions: service_role only (18)
select ok(has_function_privilege(r.role::name, f.sig, 'execute') = (r.role = 'service_role'),
          r.role || case when r.role = 'service_role' then ' can' else ' cannot' end || ' execute ' || split_part(f.sig, '(', 1))
from (values
  ('public.contribute_definition_source(uuid,text,integer,text,text,integer,text,jsonb,jsonb,integer,integer,integer,jsonb,timestamptz,integer,integer,integer,integer,bigint,integer,bigint)'),
  ('public.withdraw_definition_contributions(uuid,uuid,integer,text)'),
  ('public.report_definition_source(uuid,text,uuid,text,integer,integer,integer,jsonb,integer,integer,integer)'),
  ('public.select_definition_sources(integer,text,integer)'),
  ('public.cleanup_orphan_definition_sources()'),
  ('public.unlink_expired_definition_contributions(timestamptz,interval,interval)')
) as f(sig)
cross join (values ('anon'), ('authenticated'), ('service_role')) as r(role);

-- the internal helpers: nobody (8)
select ok(not has_function_privilege(r.role::name, f.sig, 'execute'), r.role || ' cannot execute the internal ' || split_part(f.sig, '(', 1))
from (values
  ('public.definition_source_refresh(uuid)'),
  ('public.definition_source_contribution_removed()')
) as f(sig)
cross join (values ('anon'), ('authenticated'), ('service_role'), ('public')) as r(role);

-- the private tables: nothing for clients (6)
select is(
  (select array_agg(p order by p) from unnest(array['select','insert','update','delete','truncate','references','trigger']) as p
    where has_table_privilege(g.r::name, g.t, p)),
  null::text[], g.r || ' has no privilege on ' || g.t)
from (values
  ('anon', 'public.definition_source_contributions'), ('authenticated', 'public.definition_source_contributions'),
  ('anon', 'public.definition_source_reports'), ('authenticated', 'public.definition_source_reports'),
  ('anon', 'public.definition_source_network_usage'), ('authenticated', 'public.definition_source_network_usage')
) as g(r, t);

-- definition_sources: column-level SELECT only, day-granular dates only (6)
select is(
  (select array_agg(p order by p) from unnest(array['select','insert','update','delete','truncate','references','trigger']) as p
    where has_table_privilege(g.r::name, 'public.definition_sources', p)),
  null::text[], g.r || ' has no table-level privilege on definition_sources (column-level SELECT only)')
from (values ('anon'), ('authenticated')) as g(r);
select is(
  (select bool_and(has_column_privilege(g.r::name, 'public.definition_sources', c, 'select'))
     from unnest(array['id', 'model', 'firmware', 'kind', 'raw_format', 'fact_hash', 'source', 'summary', 'quality',
                       'coverage_score', 'bytes', 'tier', 'pinned', 'contributors', 'networks', 'spot_passes',
                       'spot_failures', 'quarantined', 'first_seen_day', 'last_confirmed_day']) as c),
  true, g.r || ' can select every public definition_sources column')
from (values ('anon'), ('authenticated')) as g(r);
select is(
  (select array_agg(c order by c) from unnest(array['first_seen', 'last_confirmed_at']) as c
    where has_column_privilege(g.r::name, 'public.definition_sources', c, 'select')),
  null::text[], g.r || ' cannot select the precise first_seen / last_confirmed_at')
from (values ('anon'), ('authenticated')) as g(r);

-- RLS on (4), no address / e-mail column in the private tables (1)
select ok(c.relrowsecurity, c.relname || ' has row level security enabled')
  from pg_class c
 where c.oid in ('public.definition_sources'::regclass, 'public.definition_source_contributions'::regclass,
                 'public.definition_source_reports'::regclass, 'public.definition_source_network_usage'::regclass);
select is(
  (select count(*)::integer from information_schema.columns
    where table_schema = 'public'
      and table_name in ('definition_source_contributions', 'definition_source_reports', 'definition_source_network_usage')
      and column_name ~ '(^|_)(ip|addr|address|instance|email)(_|$)'),
  0, 'the private tables have no address, instance or e-mail column');

-- ═════════════════════════════ B. constraints (31) ═════════════════════════════

select throws_ok($$select pg_temp.put('editor-cache', '90.0', 901, p_model => 19)$$, '23514', null, 'model must be a gen-3 contributor (16, 17, 18)');
select throws_ok($$select pg_temp.put('editor-cache', '13.00', 902)$$, '23514', null, 'firmware ''13.00'' is not canonical');
select throws_ok($$select pg_temp.put('editor-cache', '013.0', 903)$$, '23514', null, 'firmware ''013.0'' is not canonical');
select throws_ok($$select pg_temp.put('editor-cache', '13', 904)$$, '23514', null, 'firmware needs a minor part');
select lives_ok($$select pg_temp.put('editor-cache', '0.0', 905)$$, 'firmware ''0.0'' is canonical');
select throws_ok($$select pg_temp.put('live-probe', '90.0', 906)$$, '23514', null, 'live-probe sources are not stored');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 907, p_raw_format => 0)$$, '23514', null, 'raw_format must be 1..100');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 908, p_fact_hash => upper(pg_temp.fh(908)))$$, '23514', null, 'fact_hash must be lowercase hex');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 909, p_quality => 4)$$, '23514', null, 'quality must be 0..3');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 910, p_bytes => 2097153)$$, '23514', null, 'bytes must not exceed 2 MiB');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 911, p_tier => 'official')$$, '23514', null, 'official must be pinned');
select lives_ok($$select pg_temp.put('editor-cache', '90.0', 911, p_tier => 'official', p_pinned => true)$$, 'a pinned official source is accepted');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 913, p_source => '{"kind":"live-full","firmware":"90.0"}')$$,
  '23514', null, 'the stored source must be of the row''s kind');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 914, p_source => '{"kind":"editor-cache"}')$$,
  '23514', null, 'the stored source must name the row''s firmware');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 915, p_source => '{"kind":"editor-cache","firmware":"90.0","id":"editor-cache@x#0"}')$$,
  '23514', null, 'a stored source carries no receiver id');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 916, p_source => '{"kind":"editor-cache","firmware":"90.0","issues":[]}')$$,
  '23514', null, 'a tolerant-parse source (issues) is not stored');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 917, p_source => jsonb_build_object('kind', 'editor-cache', 'firmware', '90.0', 'contentSha256', repeat('a', 64)))$$,
  '23514', null, 'a stored source carries no file hash');
select lives_ok($$select pg_temp.put('editor-cache', '90.0', 918, p_source => '{"kind":"editor-cache","firmware":"90.0","contentSha256":null}')$$,
  'contentSha256 null is accepted');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 921, p_source => '{"kind":"editor-cache","firmware":"90.0","contentSha256":["a"]}')$$,
  '23514', null, 'contentSha256 must be absent or null (not an array/object)');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 922, p_source => '{"kind":"editor-cache","firmware":"90.0","capturedAt":"2026-11-23T10:41:07.123Z"}')$$,
  '23514', null, 'capturedAt must be coarsened to the UTC day');
select lives_ok($$select pg_temp.put('editor-cache', '90.0', 923, p_source => '{"kind":"editor-cache","firmware":"90.0","capturedAt":"2026-11-23T00:00:00.000Z"}')$$,
  'a day-coarsened capturedAt is accepted');
select throws_ok($$select pg_temp.put('live-readonly', '90.0', 919, p_source => '{"kind":"live-readonly","firmware":"90.0","walk":{"abortReason":"x"}}')$$,
  '23514', null, 'walk.abortReason (free text) is never stored');
select throws_ok($$select pg_temp.put('editor-cache', '90.0', 920, p_summary => '[]')$$, '23514', null, 'summary must be an object');
select throws_ok($$select pg_temp.put('editor-cache', '0.0', 905)$$, '23505', null, 'one row per (model, firmware, kind, fact hash)');
select throws_ok(
  $$insert into public.definition_source_contributions (source_id, user_id, network_key, first_of_network, model, firmware, kind, consent_at, consent_version)
    values (pg_temp.sid(911, 'editor-cache', '90.0'), pg_temp.u(1), pg_temp.net(1), true, 17, '90.0', 'live-full', now(), 1)$$,
  '23503', null, 'a contribution must name its source''s model, firmware and kind');
select throws_ok(
  $$insert into public.definition_source_contributions (source_id, user_id, network_key, first_of_network, model, firmware, kind, consent_at, consent_version)
    values (pg_temp.sid(911, 'editor-cache', '90.0'), null, pg_temp.net(1), true, 17, '90.0', 'editor-cache', now(), 1)$$,
  '23514', null, 'a contribution is linked (user + network key) or unlinked (neither), never half');
select throws_ok(
  $$insert into public.definition_source_contributions (source_id, user_id, network_key, first_of_network, model, firmware, kind, consent_at, consent_version)
    values (pg_temp.sid(911, 'editor-cache', '90.0'), pg_temp.u(1), '203.0.113.7', true, 17, '90.0', 'editor-cache', now(), 1)$$,
  '23514', null, 'a network key must be a 64-hex hash, never an address');
select throws_ok(
  $$insert into public.definition_source_reports (source_id, user_id, network_key, verdict, checked, answered, mismatches)
    values (pg_temp.sid(911, 'editor-cache', '90.0'), pg_temp.u(1), pg_temp.net(1), 'passed', 24, 24, 1)$$,
  '23514', null, 'a passed report has no mismatch');
select throws_ok(
  $$insert into public.definition_source_reports (source_id, user_id, network_key, verdict, checked, answered, mismatches)
    values (pg_temp.sid(911, 'editor-cache', '90.0'), pg_temp.u(1), pg_temp.net(1), 'failed', 24, 24, 0)$$,
  '23514', null, 'a failed report has a mismatch');
select throws_ok(
  $$insert into public.definition_source_reports (source_id, user_id, network_key, verdict, checked, answered, mismatches)
    values (pg_temp.sid(911, 'editor-cache', '90.0'), pg_temp.u(1), pg_temp.net(1), 'passed', 20, 24, 0)$$,
  '23514', null, 'answered <= checked');
select throws_ok(
  $$insert into public.definition_source_reports (source_id, user_id, network_key, verdict, checked, answered, mismatches)
    values (pg_temp.sid(911, 'editor-cache', '90.0'), pg_temp.u(1), pg_temp.net(1), 'passed', 65, 24, 0)$$,
  '23514', null, 'checked <= 64');

-- ═════════════════════════════ C. quarantine and RLS visibility (12) ═════════════════════════════

select pg_temp.put('editor-cache', '20.0', 2001);
select pg_temp.put('editor-cache', '20.0', 2002, p_tier => 'verified');
select pg_temp.put('editor-cache', '20.0', 2003, p_tier => 'official', p_pinned => true);
select pg_temp.put('editor-cache', '20.0', 2004, p_tier => 'rejected', p_pinned => true);
select pg_temp.put('editor-cache', '20.0', 2005, p_failures => 3);
select pg_temp.put('editor-cache', '20.0', 2006, p_failures => 3, p_passes => 3);
select pg_temp.put('editor-cache', '20.0', 2007, p_failures => 5, p_pinned => true);
select pg_temp.put('editor-cache', '20.0', 2008, p_failures => 5, p_tier => 'verified');
select pg_temp.put('editor-cache', '20.0', 2009, p_contributors => 0);                                  -- orphan
select pg_temp.put('editor-cache', '20.0', 2010, p_contributors => 0, p_tier => 'official', p_pinned => true);  -- pinned, no votes

select is((select quarantined from public.definition_sources where id = pg_temp.sid(2005, 'editor-cache', '20.0')), true,
  'a candidate with failures from 3 networks (more than passes) is quarantined');
select is((select quarantined from public.definition_sources where id = pg_temp.sid(2006, 'editor-cache', '20.0')), false,
  'as many passes as failures: not quarantined');
select is((select quarantined from public.definition_sources where id = pg_temp.sid(2007, 'editor-cache', '20.0')), false,
  'a pinned source is never quarantined');
select is((select quarantined from public.definition_sources where id = pg_temp.sid(2008, 'editor-cache', '20.0')), false,
  'a verified source is never auto-quarantined');

set local role anon;
set local request.jwt.claims = '{"role":"anon"}';
select is(
  (select count(*)::integer from (
     select id, model, firmware, kind, raw_format, fact_hash, source, summary, quality, coverage_score, bytes, tier, pinned,
            contributors, networks, spot_passes, spot_failures, quarantined, first_seen_day, last_confirmed_day
       from public.definition_sources where firmware = '20.0') s),
  7, 'anon reads every public column of the servable sources (7 of 10)');
select is((select count(*)::integer from public.definition_sources
            where firmware = '20.0' and (tier = 'rejected' or quarantined or (not pinned and contributors = 0))), 0,
  'anon never sees a rejected, quarantined or orphaned source (a pinned one without votes stays visible)');
select throws_ok('select first_seen from public.definition_sources', '42501', null, 'anon cannot read the precise first_seen');
select throws_ok(
  $$insert into public.definition_sources (model, firmware, kind, raw_format, fact_hash, source, quality, bytes)
    values (17, '20.0', 'editor-cache', 1, repeat('c', 64), '{"kind":"editor-cache","firmware":"20.0"}', 3, 10)$$,
  '42501', null, 'anon cannot write definition_sources');
select throws_ok('select public.cleanup_orphan_definition_sources()', '42501', null, 'anon cannot execute the service functions');
reset role;

set local role authenticated;
set local request.jwt.claims = '{"sub":"d0000000-0000-4000-8000-000000000001","role":"authenticated","is_anonymous":true}';
select is((select count(*)::integer from public.definition_sources where firmware = '20.0'), 7,
  'an (anonymous) authenticated session sees the same 7 servable sources (RLS, no query filter)');
select throws_ok($$update public.definition_sources set tier = 'candidate' where firmware = '20.0'$$, '42501', null,
  'authenticated cannot update definition_sources');
select throws_ok('select user_id from public.definition_source_contributions', '42501', null,
  'authenticated cannot read contributions');
reset role;

-- ═════════════════════════════ D. ranking (19) ═════════════════════════════

-- per kind, never across kinds
select pg_temp.put('editor-cache',  '30.0', 3001, p_quality => 2, p_coverage => 50,   p_first_seen => now() - interval '10 days');
select pg_temp.put('live-readonly', '30.0', 3002, p_quality => 3, p_coverage => 5000, p_first_seen => now() - interval '10 days');
-- a NEWER truncated walk with more coverage and more contributors
select pg_temp.put('live-readonly', '30.0', 3003, p_quality => 1, p_coverage => 9000, p_contributors => 5, p_networks => 5);
select pg_temp.put('live-full',     '30.0', 3004, p_quality => 3, p_coverage => 7000);

select is((select array_agg(kind order by kind) from public.select_definition_sources(17, '30.0', 1)),
  array['editor-cache', 'live-full', 'live-readonly'], 'one best row per kind');
select is((select id from public.select_definition_sources(17, '30.0', 1) where kind = 'editor-cache'), pg_temp.sid(3001, 'editor-cache', '30.0'),
  'the editor-cache row is served although live rows have a higher quality (kinds are never compared)');
select is((select id from public.select_definition_sources(17, '30.0', 1) where kind = 'live-readonly'), pg_temp.sid(3002, 'live-readonly', '30.0'),
  'a newer truncated live row never outranks an older complete one');
select is((select string_agg(kind || '=' || alternatives, ',' order by kind) from public.select_definition_sources(17, '30.0', 1)),
  'editor-cache=1,live-full=1,live-readonly=2', 'alternatives counts the servable rows per kind');
select ok(not exists (select 1 from pg_proc p, unnest(p.proargnames) a
                       where p.proname = 'select_definition_sources' and a in ('source', 'first_seen', 'last_confirmed_at')),
  'the selection returns summaries with day-granular dates: no source body, no precise times');

-- inside one kind: tier -> quality -> coverage -> contributors -> networks -> oldest
select pg_temp.put('editor-cache', '31.0', 3101, p_first_seen => now() - interval '5 days');
select pg_temp.put('editor-cache', '31.0', 3102);
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'editor-cache'), pg_temp.sid(3101, 'editor-cache', '31.0'),
  'a newer complete row does not displace an older equal one (oldest wins the tie)');
select pg_temp.put('editor-cache', '31.0', 3103, p_contributors => 2);
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'editor-cache'), pg_temp.sid(3103, 'editor-cache', '31.0'),
  'more contributors beat age');
select pg_temp.put('editor-cache', '31.0', 3104, p_coverage => 200);
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'editor-cache'), pg_temp.sid(3104, 'editor-cache', '31.0'),
  'a higher coverage score beats more contributors');
select pg_temp.put('editor-cache', '31.0', 3105, p_quality => 2, p_coverage => 99999, p_contributors => 9, p_networks => 9);
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'editor-cache'), pg_temp.sid(3104, 'editor-cache', '31.0'),
  'quality beats coverage and contributors');
select pg_temp.put('editor-cache', '31.0', 3106, p_tier => 'verified', p_quality => 2, p_coverage => 1);
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'editor-cache'), pg_temp.sid(3106, 'editor-cache', '31.0'),
  'verified beats candidate whatever the quality');
select pg_temp.put('editor-cache', '31.0', 3107, p_tier => 'official', p_pinned => true, p_quality => 0, p_coverage => 0);
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'editor-cache'), pg_temp.sid(3107, 'editor-cache', '31.0'),
  'official beats verified');
update public.definition_sources set tier = 'rejected' where id = pg_temp.sid(3107, 'editor-cache', '31.0');
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'editor-cache'), pg_temp.sid(3106, 'editor-cache', '31.0'),
  'a rejected source is never served');
select pg_temp.put('live-full', '31.0', 3110, p_failures => 3);
select pg_temp.put('live-full', '31.0', 3111, p_quality => 1);
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'live-full'), pg_temp.sid(3111, 'live-full', '31.0'),
  'a quarantined source is never served');
select pg_temp.put('live-readonly', '31.0', 3120, p_contributors => 2, p_networks => 1, p_first_seen => now() - interval '3 days');
select pg_temp.put('live-readonly', '31.0', 3121, p_contributors => 2, p_networks => 2);
select is((select id from public.select_definition_sources(17, '31.0', 1) where kind = 'live-readonly'), pg_temp.sid(3121, 'live-readonly', '31.0'),
  'more networks beat age');
select is((select first_seen_day from public.select_definition_sources(17, '31.0', 1) where kind = 'live-readonly'), (now() at time zone 'UTC')::date,
  'the selection reports the UTC day the source was first seen');
select pg_temp.put('editor-cache', '32.0', 3201, p_raw_format => 2);
select pg_temp.put('editor-cache', '32.0', 3202, p_quality => 1);
select pg_temp.put('editor-cache', '32.0', 3203, p_contributors => 0);   -- better, but an orphan
select ok(not exists (select 1 from public.select_definition_sources(17, '32.0', 1) where id = pg_temp.sid(3203, 'editor-cache', '32.0')),
  'an orphaned source (no contribution, not pinned) is never served');
select is((select id from public.select_definition_sources(17, '32.0', 1)), pg_temp.sid(3202, 'editor-cache', '32.0'),
  'rows of a raw format the client cannot read are not served');
select is((select id from public.select_definition_sources(17, '32.0', 2)), pg_temp.sid(3201, 'editor-cache', '32.0'),
  'a client that reads the format gets the better row');
select is((select count(*)::integer from public.select_definition_sources(17, '99.9', 1)), 0, 'an unknown firmware has no rows');

-- ═════════════════════════════ E. contribute: create, dedupe, verified (19) ═════════════════════════════

select is((select concat_ws('/', created, deduped, confirmed, tier, contributors, networks) from pg_temp.share(1, 1, 1)),
  't/f/f/candidate/1/1', 'a new source is created as a candidate with one contributor');
select is(
  (select concat_ws('/', user_id = pg_temp.u(1), network_key = pg_temp.net(1), first_of_network,
                    linked_until = now() + interval '180 days', consent_version)
     from public.definition_source_contributions where source_id = pg_temp.sid(1)),
  't/t/t/t/1', 'the contribution links uploader and network key for 180 days');
select is((select count(*)::integer from public.definition_source_network_usage where network_key = pg_temp.net(1) and action = 'contribute' and bytes = 1000),
  1, 'a network usage counter is written');
select is((select concat_ws('/', quality, coverage_score, bytes, raw_format, source ->> 'kind', last_confirmed_at is null)
             from public.definition_sources where id = pg_temp.sid(1)),
  '3/100/1000/1/editor-cache/t', 'the source row stores the server-computed numbers');
select is((select concat_ws('/', created, deduped, confirmed, contributors) from pg_temp.share(1, 1, 1)),
  'f/t/f/1', 'the same uploader sharing the same facts again is deduped');
select is((select count(*)::integer from public.definition_source_contributions where user_id = pg_temp.u(1))
          + (select count(*)::integer from public.definition_source_network_usage where network_key = pg_temp.net(1)),
  2, 'a dedupe adds no contribution and charges no limit');
select is((select concat_ws('/', created, deduped, confirmed, tier, contributors, networks) from pg_temp.share(2, 2, 1)),
  'f/t/t/verified/2/2', 'a second uploader on a second network confirms the source: verified (2 users x 2 networks)');
select ok((select last_confirmed_at = now() from public.definition_sources where id = pg_temp.sid(1)), 'a confirmation sets last_confirmed_at');
select is((select count(*)::integer from public.definition_sources where model = 17 and firmware = '13.0' and kind = 'editor-cache'),
  1, 'identical facts are stored once (deduped by fact hash)');

select lives_ok($$select * from pg_temp.share(3, 3, 2, p_fw => '14.0')$$, 'an uploader shares 14.0');
select is((select concat_ws('/', confirmed, tier, contributors, networks) from pg_temp.share(4, 3, 2, p_fw => '14.0')),
  't/candidate/2/1', 'a second uploader on the SAME network is not enough (2 users x 1 network stays candidate)');
select is((select first_of_network from public.definition_source_contributions where user_id = pg_temp.u(4)), false,
  'a second contribution from a network is not first of its network');

select lives_ok($$select * from pg_temp.share(5, 5, 3, p_fw => '15.0', p_quality => 2)$$, 'an editor-cache source of quality 2 is shared');
select is((select concat_ws('/', tier, contributors, networks) from pg_temp.share(6, 6, 3, p_fw => '15.0', p_quality => 2)),
  'candidate/2/2', 'an editor-cache source whose header names another firmware (quality 2) is never auto-verified');
select lives_ok($$select * from pg_temp.share(5, 5, 4, p_kind => 'live-readonly', p_fw => '15.0', p_quality => 2)$$, 'a live source of quality 2 is shared');
select is((select concat_ws('/', tier, contributors, networks) from pg_temp.share(6, 6, 4, p_kind => 'live-readonly', p_fw => '15.0', p_quality => 2)),
  'candidate/2/2', 'a lossy live read (quality 2) is never auto-verified, even at 2 users x 2 networks');
select lives_ok($$select * from pg_temp.share(5, 5, 5, p_kind => 'live-full', p_fw => '15.0', p_quality => 2)$$, 'a lossy full read is shared');
select is((select tier from pg_temp.share(6, 6, 5, p_kind => 'live-full', p_fw => '15.0', p_quality => 3)),
  'verified', 'the same facts from a clean walk on a second network verify it');
select is((select quality from public.definition_sources where id = pg_temp.sid(5, 'live-full', '15.0')), 3::smallint,
  'a cleaner confirming walk raises the stored quality (the first walk does not cap it)');

-- ═════════════════════════════ F. one vote per uploader and kind (11) ═════════════════════════════

select lives_ok($$select * from pg_temp.share(7, 7, 10, p_fw => '16.0')$$, 'an uploader shares source 10');
select lives_ok($$select * from pg_temp.share(7, 7, 11, p_fw => '16.0')$$, 'and re-shares other facts of the same kind (source 11)');
select is(pg_temp.sid(10, 'editor-cache', '16.0'), null::uuid, 'the replaced, now orphaned source is deleted');
select is((select source_id from public.definition_source_contributions where user_id = pg_temp.u(7) and kind = 'editor-cache'),
  pg_temp.sid(11, 'editor-cache', '16.0'), 'the uploader votes for the new source only');
select lives_ok($$select * from pg_temp.share(7, 7, 12, p_kind => 'live-readonly', p_fw => '16.0')$$, 'a share of another kind');
select is((select count(*)::integer from public.definition_source_contributions where user_id = pg_temp.u(7)), 2,
  'does not replace the vote of the first kind');
select is((select tier from pg_temp.share(8, 8, 11, p_fw => '16.0')), 'verified', 'a second uploader verifies source 11');
select lives_ok($$select * from pg_temp.share(7, 7, 13, p_fw => '16.0')$$, 'the first uploader moves its vote to source 13');
select is((select concat_ws('/', tier, contributors, networks) from public.definition_sources where id = pg_temp.sid(11, 'editor-cache', '16.0')),
  'candidate/1/1', 'moving a vote away recomputes the old source (back to candidate)');
update public.definition_sources set tier = 'official', pinned = true where id = pg_temp.sid(13, 'editor-cache', '16.0');
select lives_ok($$select * from pg_temp.share(7, 7, 14, p_fw => '16.0')$$, 'the maintainer pinned source 13; its only voter moves on');
select is((select concat_ws('/', tier, pinned, contributors) from public.definition_sources where id = pg_temp.sid(13, 'editor-cache', '16.0')),
  'official/t/0', 'a pinned source survives losing its last vote');

-- ═════════════════════════════ G. limits and refusals (22) ═════════════════════════════

select lives_ok($$select * from pg_temp.share(9, 90, 40, p_fw => '40.0', p_max => 2)$$, 'uploader limit 2: first contribution');
select lives_ok($$select * from pg_temp.share(9, 91, 41, p_fw => '41.0', p_max => 2)$$, 'second contribution');
select throws_ok($$select * from pg_temp.share(9, 92, 42, p_fw => '42.0', p_max => 2)$$,
  'XQ001', 'definition_source_rate_limited', 'the third contribution in the window is refused (uploader rate)');
select is(pg_temp.detail_of($$select * from pg_temp.share(9, 92, 42, p_fw => '42.0', p_max => 2)$$), '3600',
  'XQ001 carries the retry seconds (the oldest contribution leaves the 1 h window)');
select is((select deduped from pg_temp.share(9, 90, 40, p_fw => '40.0', p_max => 2)), true,
  'a retry of an existing contribution is still answered at the limit');

select lives_ok($$select * from pg_temp.share(10, 50, 43, p_fw => '43.0', p_netmax => 2)$$, 'network limit 2: first uploader');
select lives_ok($$select * from pg_temp.share(11, 50, 44, p_fw => '44.0', p_netmax => 2)$$, 'a second, fresh uploader on the same network');
select throws_ok($$select * from pg_temp.share(12, 50, 45, p_fw => '45.0', p_netmax => 2)$$,
  'XQ005', 'definition_source_network_rate_limited', 'a third fresh uploader on that network is refused (network rate)');
select is(pg_temp.wd(10), '1/1', 'the first uploader withdraws');
select throws_ok($$select * from pg_temp.share(12, 50, 45, p_fw => '45.0', p_netmax => 2)$$,
  'XQ005', 'definition_source_network_rate_limited', 'withdrawing does not reset the network limit');

select lives_ok($$select * from pg_temp.share(13, 93, 46, p_fw => '46.0', p_quota => 1500)$$, 'uploader quota 1500 bytes: 1000 fit');
select throws_ok($$select * from pg_temp.share(13, 94, 47, p_fw => '47.0', p_quota => 1500)$$,
  'XQ002', 'definition_source_quota_exceeded', 'another 1000 bytes exceed the uploader quota');
select is(pg_temp.detail_of($$select * from pg_temp.share(13, 94, 47, p_fw => '47.0', p_quota => 1500)$$), '2592000',
  'XQ002 carries the retry seconds (the charged contribution leaves the 30-day window)');
select lives_ok($$select * from pg_temp.share(14, 60, 48, p_fw => '48.0', p_netquota => 1500)$$, 'network quota 1500 bytes: 1000 fit');
select throws_ok($$select * from pg_temp.share(15, 60, 49, p_fw => '49.0', p_netquota => 1500)$$,
  'XQ006', 'definition_source_network_quota_exceeded', 'another uploader on that network exceeds the network quota');
select is(pg_temp.detail_of($$select * from pg_temp.share(15, 60, 49, p_fw => '49.0', p_netquota => 1500)$$), '2592000',
  'XQ006 carries the retry seconds');

-- accepted residual, pinned: withdraw + re-share churn passes the uploader limit (it counts current contributions),
-- the network limit catches it (its counters outlive the withdrawals)
select * from pg_temp.share(16, 95, 50, p_fw => '50.0', p_max => 2);
select pg_temp.wd(16);
select * from pg_temp.share(16, 95, 51, p_fw => '51.0', p_max => 2);
select pg_temp.wd(16);
select lives_ok($$select * from pg_temp.share(16, 95, 52, p_fw => '52.0', p_max => 2)$$,
  'residual: a third share after withdraw/re-share churn passes the uploader limit of 2');
select is((select count(*)::integer from public.definition_source_network_usage where network_key = pg_temp.net(95) and action = 'contribute'), 3,
  'every churned share stays on the network counter');
select throws_ok($$select * from pg_temp.share(16, 95, 53, p_fw => '53.0', p_netmax => 3)$$,
  'XQ005', 'definition_source_network_rate_limited', 'so the network limit stops the churn');

-- maintainer-rejected facts are refused before anything moves
select * from pg_temp.share(18, 18, 70, p_fw => '24.0');
update public.definition_sources set tier = 'rejected', pinned = true where id = pg_temp.sid(70, 'editor-cache', '24.0');
select * from pg_temp.share(17, 17, 71, p_fw => '24.0');
select throws_ok($$select * from pg_temp.share(17, 17, 70, p_fw => '24.0')$$,
  'XQ007', 'definition_source_rejected', 'contributing facts the maintainer rejected is refused');
select is((select source_id from public.definition_source_contributions where user_id = pg_temp.u(17)), pg_temp.sid(71, 'editor-cache', '24.0'),
  'the uploader''s vote is not moved');
select is((select count(*)::integer from public.definition_source_network_usage where network_key = pg_temp.net(17)), 1,
  'and no limit is charged');

-- ═════════════════════════════ H. withdraw and direct deletes (12) ═════════════════════════════

select * from pg_temp.share(20, 20, 20, p_fw => '17.0');
select * from pg_temp.share(21, 21, 21, p_fw => '17.0');
select * from pg_temp.share(22, 22, 21, p_fw => '17.0');
select is(pg_temp.wd(20, pg_temp.sid(20, 'editor-cache', '17.0')), '1/1', 'withdrawing the only contribution deletes the orphaned source');
select is(pg_temp.sid(20, 'editor-cache', '17.0'), null::uuid, 'the source is gone');
select is(pg_temp.wd(21, pg_temp.sid(21, 'editor-cache', '17.0')), '1/0', 'withdrawing one of two contributions keeps the source');
select is((select concat_ws('/', contributors, networks, tier) from public.definition_sources where id = pg_temp.sid(21, 'editor-cache', '17.0')),
  '1/1/candidate', 'and recomputes its counters and tier');
select is(pg_temp.wd(20, pg_temp.sid(21, 'editor-cache', '17.0')), '0/0', 'another uploader''s source id withdraws nothing');
select is(pg_temp.wd(21, gen_random_uuid()), '0/0', 'an unknown source id withdraws nothing');
update public.definition_sources set tier = 'official', pinned = true where id = pg_temp.sid(21, 'editor-cache', '17.0');
select is(pg_temp.wd(22), '1/0', 'withdraw all: a pinned source is not deleted');
select is((select concat_ws('/', tier, contributors) from public.definition_sources where id = pg_temp.sid(21, 'editor-cache', '17.0')),
  'official/0', 'the pinned source stays without contributions');
select * from pg_temp.share(23, 23, 23, p_fw => '18.0');
select * from pg_temp.share(23, 23, 24, p_fw => '19.0');
select is(pg_temp.wd(23, null, 17, '18.0'), '1/1', 'withdraw all for one firmware');
select ok(pg_temp.sid(24, 'editor-cache', '19.0') is not null, 'leaves the other firmware alone');
select is(pg_temp.wd(23), '1/1', 'withdraw all removes the rest');
select * from pg_temp.share(24, 24, 25, p_fw => '25.0');
select * from pg_temp.share(25, 25, 25, p_fw => '25.0');
set local role service_role;
delete from public.definition_source_contributions where user_id = 'd0000000-0000-4000-8000-000000000025';
reset role;
select is((select concat_ws('/', tier, contributors, networks) from public.definition_sources where id = pg_temp.sid(25, 'editor-cache', '25.0')),
  'candidate/1/1', 'a direct service-role DELETE of a contribution fires the trigger: counters and tier recomputed');

-- ═════════════════════════════ I. reports and quarantine (18) ═════════════════════════════

select * from pg_temp.share(30, 30, 30, p_fw => '21.0');                               -- R: candidate
select * from pg_temp.share(30, 30, 31, p_kind => 'live-readonly', p_fw => '21.0');    -- RV: verified
select * from pg_temp.share(31, 31, 31, p_kind => 'live-readonly', p_fw => '21.0');

select is(pg_temp.rep(32, 32, pg_temp.sid(30, 'editor-cache', '21.0'), 'failed'), false, 'one failure report does not quarantine');
select is((select concat_ws('/', spot_passes, spot_failures) from public.definition_sources where id = pg_temp.sid(30, 'editor-cache', '21.0')),
  '0/1', 'spot_failures counts the reporting network');
select pg_temp.rep(33, 33, pg_temp.sid(30, 'editor-cache', '21.0'), 'failed');
select is(pg_temp.rep(34, 34, pg_temp.sid(30, 'editor-cache', '21.0'), 'failed'), true,
  'failures from 3 networks (more than passes) quarantine a candidate');
select is((select count(*)::integer from public.select_definition_sources(17, '21.0', 1) where kind = 'editor-cache'), 0,
  'the quarantined source is no longer served');
select pg_temp.rep(35, 34, pg_temp.sid(30, 'editor-cache', '21.0'), 'failed');
select is((select spot_failures from public.definition_sources where id = pg_temp.sid(30, 'editor-cache', '21.0')), 3,
  'two reporters on one network count once');
select pg_temp.rep(36, 36, pg_temp.sid(30, 'editor-cache', '21.0'), 'passed');
select pg_temp.rep(37, 37, pg_temp.sid(30, 'editor-cache', '21.0'), 'passed');
select is((select quarantined from public.definition_sources where id = pg_temp.sid(30, 'editor-cache', '21.0')), true,
  'two passes against three failures keep it quarantined');
select is(pg_temp.rep(38, 38, pg_temp.sid(30, 'editor-cache', '21.0'), 'passed'), false, 'as many passes as failures lift the quarantine');
select pg_temp.rep(32, 32, pg_temp.sid(30, 'editor-cache', '21.0'), 'passed');
select is((select string_agg(verdict, ',') from public.definition_source_reports
            where source_id = pg_temp.sid(30, 'editor-cache', '21.0') and user_id = pg_temp.u(32)),
  'passed', 'a repeated report replaces the uploader''s earlier one');
delete from public.definition_source_reports where source_id = pg_temp.sid(30, 'editor-cache', '21.0');
select pg_temp.rep(39, 39, pg_temp.sid(30, 'editor-cache', '21.0'), 'failed');
select is((select concat_ws('/', spot_passes, spot_failures, quarantined) from public.definition_sources where id = pg_temp.sid(30, 'editor-cache', '21.0')),
  '4/3/f', 'the counters are high-water marks: deleted reports do not lower them');
select pg_temp.rep(40, 40, pg_temp.sid(31, 'live-readonly', '21.0'), 'failed');
select pg_temp.rep(41, 41, pg_temp.sid(31, 'live-readonly', '21.0'), 'failed');
select is(pg_temp.rep(42, 42, pg_temp.sid(31, 'live-readonly', '21.0'), 'failed'), false, 'a verified source is never auto-quarantined');
select is((select concat_ws('/', tier, spot_failures) from public.definition_sources where id = pg_temp.sid(31, 'live-readonly', '21.0')),
  'verified/3', 'its failures are still counted (maintainer view)');
select is(pg_temp.rep(32, 32, gen_random_uuid(), 'passed'), null::boolean, 'a report on an unknown source returns no row');
select pg_temp.rep(43, 43, pg_temp.sid(30, 'editor-cache', '21.0'), 'passed', p_max => 1);
select throws_ok($$select pg_temp.rep(43, 43, pg_temp.sid(31, 'live-readonly', '21.0'), 'passed', p_max => 1)$$,
  'XQ001', 'definition_report_rate_limited', 'the uploader report limit');
select pg_temp.rep(44, 45, pg_temp.sid(30, 'editor-cache', '21.0'), 'passed', p_netmax => 1);
select throws_ok($$select pg_temp.rep(46, 45, pg_temp.sid(31, 'live-readonly', '21.0'), 'passed', p_netmax => 1)$$,
  'XQ005', 'definition_report_network_rate_limited', 'the network report limit');
select throws_ok(
  $$select * from public.report_definition_source(pg_temp.u(1), pg_temp.net(1), pg_temp.sid(30, 'editor-cache', '21.0'), 'maybe', 24, 24, 0, '{}'::jsonb)$$,
  '22023', null, 'a verdict must be passed or failed');
select * from pg_temp.share(30, 30, 32, p_kind => 'live-full', p_fw => '21.0');        -- R2, contributor u30 on network 30
select pg_temp.rep(47, 47, pg_temp.sid(32, 'live-full', '21.0'), 'failed');
select pg_temp.rep(47, 48, pg_temp.sid(32, 'live-full', '21.0'), 'failed');
select is((select spot_failures from public.definition_sources where id = pg_temp.sid(32, 'live-full', '21.0')), 1,
  'a re-report from another network replaces the first: it does not add a network');
select pg_temp.rep(30, 49, pg_temp.sid(32, 'live-full', '21.0'), 'failed');
select is((select count(*)::integer || '/' || (select spot_failures from public.definition_sources where id = pg_temp.sid(32, 'live-full', '21.0'))
             from public.definition_source_reports where source_id = pg_temp.sid(32, 'live-full', '21.0') and user_id = pg_temp.u(30)),
  '1/1', 'a contributor''s own report is stored but not counted');
select pg_temp.rep(48, 30, pg_temp.sid(32, 'live-full', '21.0'), 'failed');
select is((select spot_failures from public.definition_sources where id = pg_temp.sid(32, 'live-full', '21.0')), 1,
  'a report from a contributor''s network is not counted either');

-- ═════════════════════════════ J. unlink at 180 days (6) ═════════════════════════════

select * from pg_temp.share(50, 50, 50, p_fw => '22.0');
select * from pg_temp.share(51, 51, 50, p_fw => '22.0');
select pg_temp.rep(52, 52, pg_temp.sid(50, 'editor-cache', '22.0'), 'failed');
-- time shift: an expired link, a 200-day-old report and a 40-day-old usage counter
update public.definition_source_contributions set linked_until = now() - interval '1 day' where user_id = pg_temp.u(50);
update public.definition_source_reports set created_at = now() - interval '200 days' where user_id = pg_temp.u(52);
update public.definition_source_network_usage set created_at = now() - interval '40 days' where network_key = pg_temp.net(52);

select is((select concat_ws('/', unlinked, reports_deleted, usage_deleted) from public.unlink_expired_definition_contributions()),
  '1/1/1', 'the sweep unlinks expired links and prunes old reports and usage counters');
select is((select count(*)::integer from public.definition_source_contributions
            where source_id = pg_temp.sid(50, 'editor-cache', '22.0') and user_id is null and network_key is null),
  1, 'the expired contribution is unlinked: no user id, no network key');
select is((select concat_ws('/', app::text, consent_at = date_trunc('day', now(), 'UTC')) from public.definition_source_contributions
            where source_id = pg_temp.sid(50, 'editor-cache', '22.0') and user_id is null),
  '{}/t', 'unlinking also clears the app stamps and coarsens the consent time to the UTC day');
select is((select concat_ws('/', tier, contributors, networks, spot_failures) from public.definition_sources where id = pg_temp.sid(50, 'editor-cache', '22.0')),
  'verified/2/2/1', 'unlinking keeps the counters, the tier and the high-water report count');
select is(pg_temp.wd(50), '0/0', 'an unlinked contribution can no longer be withdrawn');
select is((select count(*)::integer from public.select_definition_sources(17, '22.0', 1)), 1, 'its content stays published');

-- ═════════════════════════════ K. account deletion and orphan cleanup (9) ═════════════════════════════
-- (delete-account calls withdraw_definition_contributions first — section H; this is the cascade fallback)

select * from pg_temp.share(60, 60, 60, p_fw => '23.0');
select * from pg_temp.share(61, 61, 60, p_fw => '23.0');
select * from pg_temp.share(60, 60, 61, p_kind => 'live-readonly', p_fw => '23.0');
select pg_temp.rep(60, 60, pg_temp.sid(60, 'editor-cache', '23.0'), 'passed');
delete from auth.users where id = pg_temp.u(60);

select is((select count(*)::integer from public.definition_source_contributions where user_id = pg_temp.u(60))
          + (select count(*)::integer from public.definition_source_reports where user_id = pg_temp.u(60)),
  0, 'deleting the auth user removes its contributions and reports');
select is((select concat_ws('/', tier, contributors, networks) from public.definition_sources where id = pg_temp.sid(60, 'editor-cache', '23.0')),
  'candidate/1/1', 'the cascade recomputes the counters and tier of the sources it touched');
select is((select contributors from public.definition_sources where id = pg_temp.sid(61, 'live-readonly', '23.0')), 0,
  'a source left without contributions waits for the orphan cleanup');
select is((select count(*)::integer from public.select_definition_sources(17, '23.0', 1) where kind = 'live-readonly'), 0,
  'meanwhile it is not served');
set local role anon;
select is((select count(*)::integer from public.definition_sources where firmware = '23.0' and kind = 'live-readonly'), 0,
  'nor visible to clients');
reset role;
create temp table orphans_before as
  select count(*)::integer as n from public.definition_sources s
   where not s.pinned and not exists (select 1 from public.definition_source_contributions c where c.source_id = s.id);
select is(public.cleanup_orphan_definition_sources(), (select n from orphans_before), 'the cleanup deletes every unpinned source without contributions');
select is(pg_temp.sid(61, 'live-readonly', '23.0'), null::uuid, 'including the one the deleted account left behind');
select ok(pg_temp.sid(60, 'editor-cache', '23.0') is not null and pg_temp.sid(13, 'editor-cache', '16.0') is not null,
  'sources with contributions and pinned sources are kept');
delete from auth.users where id = pg_temp.u(50);
select is((select contributors from public.definition_sources where id = pg_temp.sid(50, 'editor-cache', '22.0')), 2,
  'an unlinked contribution is no longer tied to its account and survives its deletion');

-- ═════════════════════════════ L. argument checks (3) ═════════════════════════════

select throws_ok(
  $$select * from public.contribute_definition_source(pg_temp.u(1), '203.0.113.7', 17, '13.0', 'editor-cache', 1, pg_temp.fh(99),
      pg_temp.src('editor-cache', '13.0'), '{}'::jsonb, 3, 1, 10, '{}'::jsonb, now(), 1)$$,
  '22023', null, 'a network key that is not a 64-hex hash (e.g. a raw address) is refused');
select throws_ok(
  $$select * from public.contribute_definition_source(pg_temp.u(1), pg_temp.net(1), 17, '13.0', 'live-probe', 1, pg_temp.fh(99),
      pg_temp.src('live-probe', '13.0'), '{}'::jsonb, 3, 1, 10, '{}'::jsonb, now(), 1)$$,
  '22023', null, 'live-probe sources cannot be contributed');
select throws_ok($$select * from public.withdraw_definition_contributions(null)$$, '22023', null, 'withdraw needs an uploader');

-- ═════════════════════════════ M. an orphan is reset, not revived (7) ═════════════════════════════
-- (20261201121000_definition_sources_orphan_reset.sql: an identical share of an unpinned source without contributions
-- starts a fresh row; a pinned one is confirmed as before)

select pg_temp.put('editor-cache', '25.0', 2501, p_contributors => 0, p_networks => 0, p_failures => 5,
  p_first_seen => now() - interval '100 days', p_summary => '{"old": true}'::jsonb,
  p_source => jsonb_build_object('kind', 'editor-cache', 'firmware', '25.0', 'codecVersion', '0.0.0-old', 'records', '[]'::jsonb));
create temp table orphan_before as select pg_temp.sid(2501, 'editor-cache', '25.0') as id;
select is((select concat_ws('/', created, deduped, confirmed, tier, contributors, networks) from pg_temp.share(62, 62, 2501, p_fw => '25.0')),
  't/f/f/candidate/1/1', 'an identical share of an orphan creates a fresh row (not a confirmation)');
select isnt(pg_temp.sid(2501, 'editor-cache', '25.0'), (select id from orphan_before), 'with a new id (the orphan is gone)');
select is((select concat_ws('/', first_seen = now(), summary = '{}'::jsonb, source ->> 'codecVersion', spot_failures, quarantined)
             from public.definition_sources where id = pg_temp.sid(2501, 'editor-cache', '25.0')),
  't/t/0.0.0-test/0/f', 'the new uploader''s body, summary and date; no inherited reports or quarantine');

select pg_temp.put('editor-cache', '25.0', 2502, p_contributors => 0, p_networks => 0, p_tier => 'official', p_pinned => true);
create temp table pinned_before as select pg_temp.sid(2502, 'editor-cache', '25.0') as id;
select is((select concat_ws('/', created, deduped, confirmed, tier, contributors) from pg_temp.share(63, 63, 2502, p_fw => '25.0')),
  'f/t/t/official/1', 'a pinned source without contributions is confirmed, never reset');
select is(pg_temp.sid(2502, 'editor-cache', '25.0'), (select id from pinned_before), 'and keeps its id');

select pg_temp.put('editor-cache', '25.0', 2503, p_contributors => 0, p_networks => 0);
create temp table limited_before as select pg_temp.sid(2503, 'editor-cache', '25.0') as id;
select throws_ok($$select * from pg_temp.share(64, 64, 2503, p_fw => '25.0', p_max => 0)$$, 'XQ001', null,
  'a share refused by a limit fails as a whole');
select is(pg_temp.sid(2503, 'editor-cache', '25.0'), (select id from limited_before),
  'and leaves the orphan as it was (the reset is rolled back with it)');

select * from finish();
rollback;
