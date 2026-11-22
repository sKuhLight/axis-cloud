-- pgTAP tests for 20261121150000_explicit_grants.sql: the Data API roles (anon, authenticated,
-- service_role) get exactly the table and function privileges the RLS policies and the edge functions
-- use, so the schema works on Supabase projects created with the secure defaults (no implicit grants).
--
-- Positive checks (a needed privilege exists) hold on every stack. Negative checks are limited to what is
-- denied on EVERY stack once all migrations are applied: the diagnostic_captures and editor_cache_* revokes
-- (20261123120000_editor_cache_uploads.sql grants its tables to service_role only), the hardened quota
-- functions, nothing for PUBLIC, device_profiles.created_by (the migration revokes the table-level SELECT
-- from anon/authenticated and grants only the other columns, so uploader ids are unreadable on old and new
-- stacks alike), and RLS-gated writes that fail with 42501 whether the privilege is missing (new default)
-- or RLS rejects the row (older, broader implicit grants).
--
-- Run against a LOCAL stack only (it needs the migrations applied and creates throw-away rows inside a
-- transaction that is rolled back):
--   npx --yes supabase@latest start
--   npx --yes supabase@latest db reset
--   npx --yes supabase@latest test db
begin;
create extension if not exists pgtap with schema extensions;

select plan(103);

insert into auth.users (id, email) values
  ('11111111-1111-4111-8111-111111111111', 'grants-a@example.test');

-- a shared, public device profile to read as anon / authenticated (inserted as the table owner)
insert into public.device_profiles (model, firmware, content_hash, profile, source)
  values (17, '12.0', 'grants-test-1', '{}'::jsonb, 'live-walk');

-- ── functions: who may execute what (8) ──
select is(has_function_privilege('authenticated', 'public.is_paid(uuid)', 'execute'), true, 'authenticated can execute is_paid (called by preset_quota)');
select is(has_function_privilege('service_role', 'public.is_paid(uuid)', 'execute'), true, 'service_role can execute is_paid');
select is(has_function_privilege('anon', 'public.is_paid(uuid)', 'execute'), false, 'anon cannot execute is_paid');
select is(has_function_privilege('authenticated', 'public.preset_quota()', 'execute'), true, 'authenticated can execute preset_quota');
select is(has_function_privilege('service_role', 'public.preset_quota()', 'execute'), true, 'service_role can execute preset_quota');
select is(has_function_privilege('anon', 'public.preset_quota()', 'execute'), false, 'anon cannot execute preset_quota');
select is(has_function_privilege('anon', 'public.enforce_preset_quota()', 'execute'), false, 'anon cannot execute the trigger-only enforce_preset_quota');
select is(has_function_privilege('authenticated', 'public.enforce_preset_quota()', 'execute'), false, 'authenticated cannot execute the trigger-only enforce_preset_quota');

-- ── tables: the granted privileges (40; device_profiles for anon/authenticated is column-level, below) ──
select ok(
  has_table_privilege(g.grantee::name, 'public.' || g.tbl, g.priv),
  g.grantee || ' has ' || upper(g.priv) || ' on ' || g.tbl)
from (values
  -- authenticated: per-user tables (RLS `for all`) ...
  ('authenticated', 'documents',         'select'),
  ('authenticated', 'documents',         'insert'),
  ('authenticated', 'documents',         'update'),
  ('authenticated', 'documents',         'delete'),
  ('authenticated', 'preset_versions',   'select'),
  ('authenticated', 'preset_versions',   'insert'),
  ('authenticated', 'preset_versions',   'update'),
  ('authenticated', 'preset_versions',   'delete'),
  ('authenticated', 'backups',           'select'),
  ('authenticated', 'backups',           'insert'),
  ('authenticated', 'backups',           'update'),
  ('authenticated', 'backups',           'delete'),
  -- ... and read-only tables (anon/authenticated read device_profiles per column only: see below)
  ('authenticated', 'subscriptions',     'select'),
  ('authenticated', 'tier_limits',       'select'),
  -- service_role: what delete-account, gc-blobs, device-profiles, diagnostic-captures and the maintainer use
  ('service_role',  'documents',         'select'),
  ('service_role',  'documents',         'delete'),
  ('service_role',  'preset_versions',   'select'),
  ('service_role',  'preset_versions',   'delete'),
  ('service_role',  'backups',           'select'),
  ('service_role',  'backups',           'delete'),
  ('service_role',  'subscriptions',     'select'),
  ('service_role',  'subscriptions',     'insert'),
  ('service_role',  'subscriptions',     'update'),
  ('service_role',  'subscriptions',     'delete'),
  ('service_role',  'tier_limits',       'select'),
  ('service_role',  'tier_limits',       'insert'),
  ('service_role',  'tier_limits',       'update'),
  ('service_role',  'device_profiles',   'select'),
  ('service_role',  'device_profiles',   'insert'),
  ('service_role',  'diagnostic_captures', 'select'),
  ('service_role',  'diagnostic_captures', 'update'),
  ('service_role',  'diagnostic_captures', 'delete'),
  -- editor-caches function + gc-blobs + delete-account + maintainer (rows are created by the definer functions)
  ('service_role',  'editor_cache_uploads',  'select'),
  ('service_role',  'editor_cache_uploads',  'update'),
  ('service_role',  'editor_cache_uploads',  'delete'),
  ('service_role',  'editor_cache_coverage', 'select'),
  ('service_role',  'editor_cache_coverage', 'insert'),
  ('service_role',  'editor_cache_coverage', 'update'),
  ('service_role',  'editor_cache_ip_usage', 'select'),
  ('service_role',  'editor_cache_ip_usage', 'delete')
) as g(grantee, tbl, priv);

-- ── the editor-cache tables stay closed to clients (6) ──
select is(
  (select array_agg(p order by p) from unnest(array['select','insert','update','delete','truncate','references','trigger']) as p
    where has_table_privilege(g.r::name, g.t, p)),
  null::text[], g.r || ' has no privilege on ' || g.t)
from (values
  ('anon', 'public.editor_cache_uploads'), ('authenticated', 'public.editor_cache_uploads'),
  ('anon', 'public.editor_cache_coverage'), ('authenticated', 'public.editor_cache_coverage'),
  ('anon', 'public.editor_cache_ip_usage'), ('authenticated', 'public.editor_cache_ip_usage')
) as g(r, t);

-- ── diagnostic_captures stays closed to clients (2) ──
select is(
  (select array_agg(p order by p) from unnest(array['select','insert','update','delete','truncate','references','trigger']) as p
    where has_table_privilege('anon', 'public.diagnostic_captures', p)),
  null::text[], 'anon has no privilege on diagnostic_captures');
select is(
  (select array_agg(p order by p) from unnest(array['select','insert','update','delete','truncate','references','trigger']) as p
    where has_table_privilege('authenticated', 'public.diagnostic_captures', p)),
  null::text[], 'authenticated has no privilege on diagnostic_captures');

-- ── device_profiles: public columns readable by anon/authenticated, created_by (uploader ids) not (4) ──
-- Column-level on purpose: the uploader's user id must not be readable through the Data API (with
-- is_paid(uuid) it would reveal who is a supporter). has_column_privilege is also true for a table-level
-- grant, so the created_by checks fail if SELECT is ever granted on the whole table again.
select is(
  (select bool_and(has_column_privilege('anon', 'public.device_profiles', c, 'select'))
     from unnest(array['id', 'model', 'firmware', 'content_hash', 'profile', 'source', 'record_count', 'created_at']) as c),
  true, 'anon can select every public device_profiles column');
select is(has_column_privilege('anon', 'public.device_profiles', 'created_by', 'select'), false, 'anon cannot select device_profiles.created_by');
select is(
  (select bool_and(has_column_privilege('authenticated', 'public.device_profiles', c, 'select'))
     from unnest(array['id', 'model', 'firmware', 'content_hash', 'profile', 'source', 'record_count', 'created_at']) as c),
  true, 'authenticated can select every public device_profiles column');
select is(has_column_privilege('authenticated', 'public.device_profiles', 'created_by', 'select'), false, 'authenticated cannot select device_profiles.created_by');

-- ── nothing for PUBLIC (4) ──
select is(has_table_privilege('public', 'public.documents', 'select'), false, 'PUBLIC has no SELECT on documents');
select is(has_function_privilege('public', 'public.is_paid(uuid)', 'execute'), false, 'PUBLIC cannot execute is_paid');
select is(has_function_privilege('public', 'public.preset_quota()', 'execute'), false, 'PUBLIC cannot execute preset_quota');
select is(has_function_privilege('public', 'public.enforce_preset_quota()', 'execute'), false, 'PUBLIC cannot execute enforce_preset_quota');

-- ── authenticated: the sync flows work through RLS (19) ──
set local role authenticated;
set local request.jwt.claims = '{"sub":"11111111-1111-4111-8111-111111111111","role":"authenticated"}';
set local request.jwt.claim.sub = '11111111-1111-4111-8111-111111111111';

select lives_ok(
  $$insert into public.documents (user_id, collection, id, data, updated_at)
    values ('11111111-1111-4111-8111-111111111111', 'config', 'k', '{}'::jsonb, 1)$$,
  'authenticated can insert its own document');
select is((select count(*)::integer from public.documents), 1, 'authenticated reads its own document');
-- the real sync write (cloud.ts supabase-js .upsert(..., { onConflict: 'user_id,collection,id' })): PostgREST sends
-- insert ... on conflict (...) do update set <every column> = excluded.<column>, i.e. it needs INSERT, UPDATE and SELECT
select lives_ok(
  $$insert into public.documents (user_id, collection, id, data, updated_at, rev, deleted)
    values ('11111111-1111-4111-8111-111111111111', 'config', 'k', '{"v":2}'::jsonb, 5, 1, false)
    on conflict (user_id, collection, id) do update
      set user_id = excluded.user_id, collection = excluded.collection, id = excluded.id, data = excluded.data,
          updated_at = excluded.updated_at, rev = excluded.rev, deleted = excluded.deleted$$,
  'authenticated can upsert its own document (insert ... on conflict do update)');
select is((select updated_at from public.documents where id = 'k'), 5::bigint, 'the upsert updated the existing row');
select lives_ok($$update public.documents set rev = 2 where id = 'k'$$, 'authenticated can update its own document');
select is((select rev from public.documents where id = 'k'), 2, 'the update took effect');
select lives_ok($$delete from public.documents where id = 'k'$$, 'authenticated can delete its own document');
select is((select count(*)::integer from public.documents), 0, 'the document is gone');

-- the BEFORE INSERT trigger enforce_preset_quota fires although the caller has no EXECUTE on it: EXECUTE on a
-- trigger function is checked when the trigger is created, not when it fires (so no grant is needed)
select lives_ok(
  $$insert into public.preset_versions (user_id, id, location, crc, name, model, captured_at, source, bytes, stored, blob_path)
    values ('11111111-1111-4111-8111-111111111111', 'v1', 0, 1, 'n', 'FM3', 1, 'manual', 10, 10, '11111111-1111-4111-8111-111111111111/blobs/x.br')$$,
  'authenticated can insert a preset version (quota trigger fires without an EXECUTE grant)');
select is((((select public.preset_quota())->>'snapshots')::integer), 1, 'authenticated can call preset_quota (reads preset_versions, tier_limits, is_paid)');
select lives_ok($$delete from public.preset_versions where id = 'v1'$$, 'authenticated can delete its own preset version');
select lives_ok(
  $$insert into public.backups (user_id, id, created_at)
    values ('11111111-1111-4111-8111-111111111111', 'b1', 1)$$,
  'authenticated can insert its own backup row');

select lives_ok('select * from public.subscriptions', 'authenticated can read subscriptions (own row only, via RLS)');
select is((select count(*)::integer from public.tier_limits where tier = 'free'), 1, 'authenticated can read tier_limits');
select is(
  (select count(*)::integer from (
     select id, model, firmware, content_hash, profile, source, record_count, created_at
       from public.device_profiles where content_hash = 'grants-test-1') s),
  1, 'authenticated can read the public device_profiles columns');
select throws_ok('select created_by from public.device_profiles', '42501', null, 'authenticated cannot read device_profiles.created_by');

select throws_ok(
  $$insert into public.subscriptions (user_id, active) values ('11111111-1111-4111-8111-111111111111', true)$$,
  '42501', null, 'authenticated cannot grant itself a subscription');
select throws_ok(
  $$insert into public.tier_limits (tier, max_stored_bytes, max_snapshots, max_backups) values ('hax', 1, 1, 1)$$,
  '42501', null, 'authenticated cannot write tier_limits');
select throws_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source)
    values (17, '12.0', 'grants-test-x', '{}'::jsonb, 'live-walk')$$,
  '42501', null, 'authenticated cannot write device_profiles');
reset role;

-- ── anon: public device-profile read only, without created_by (3) ──
set local role anon;
set local request.jwt.claims = '{"role":"anon"}';
set local request.jwt.claim.sub = '';
select is(
  (select count(*)::integer from (
     select id, model, firmware, content_hash, profile, source, record_count, created_at
       from public.device_profiles where content_hash = 'grants-test-1') s),
  1, 'anon can read the public device_profiles columns');
select throws_ok('select created_by from public.device_profiles', '42501', null, 'anon cannot read device_profiles.created_by');
select throws_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source)
    values (17, '12.0', 'grants-test-y', '{}'::jsonb, 'live-walk')$$,
  '42501', null, 'anon cannot write device_profiles');
reset role;

-- ── service_role: the edge-function and maintainer flows work (17) ──
set local role service_role;

-- subscriptions: written by the service role (Patreon link / maintainer), read by is_paid
select lives_ok(
  $$insert into public.subscriptions (user_id, active, plan, source)
    values ('11111111-1111-4111-8111-111111111111', true, 'Supporter', 'patreon')$$,
  'service_role can insert a subscription');
select is(public.is_paid('11111111-1111-4111-8111-111111111111'), true, 'service_role can execute is_paid and sees the new subscription');
select lives_ok($$update public.subscriptions set plan = 'Free' where user_id = '11111111-1111-4111-8111-111111111111'$$, 'service_role can update a subscription');

-- tier_limits (maintainer tuning) and device-profiles POST
select lives_ok($$update public.tier_limits set max_snapshots = max_snapshots where tier = 'free'$$, 'service_role can update tier_limits');
select lives_ok(
  $$insert into public.device_profiles (model, firmware, content_hash, profile, source)
    values (17, '12.0', 'grants-test-2', '{}'::jsonb, 'live-walk')$$,
  'service_role can insert device_profiles');
select is((select count(*)::integer from public.device_profiles where content_hash like 'grants-test-%'), 2, 'service_role can read device_profiles');

-- diagnostic-captures function: reserve (rpc), finalize (update), maintainer read, delete
select lives_ok(
  $$select * from public.reserve_diagnostic_capture('11111111-1111-4111-8111-111111111111', 'grants-1', 17, null, '{}'::jsonb, 'done', 1000)$$,
  'service_role can reserve a diagnostic capture');
select lives_ok(
  $$update public.diagnostic_captures set status = 'complete' where user_id = '11111111-1111-4111-8111-111111111111' and capture_id = 'grants-1'$$,
  'service_role can finalize a diagnostic capture');
select is((select count(*)::integer from public.diagnostic_captures where user_id = '11111111-1111-4111-8111-111111111111'), 1, 'service_role can read diagnostic_captures');
select lives_ok($$delete from public.diagnostic_captures where user_id = '11111111-1111-4111-8111-111111111111'$$, 'service_role can delete diagnostic_captures');

-- editor-caches function: reserve (rpc) and read back (complete/delete are covered by editor_cache_uploads.test.sql)
select lives_ok(
  $$select * from public.reserve_editor_cache_upload('11111111-1111-4111-8111-111111111111', repeat('e', 64), 17, '13.0', '13.0', null,
      'effectDefinitions_11_13p0.cache', repeat('b', 64), 1000, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, now(), 1)$$,
  'service_role can reserve an editor-cache upload');
select is((select count(*)::integer from public.editor_cache_uploads where user_id = '11111111-1111-4111-8111-111111111111'), 1, 'service_role can read editor_cache_uploads');

-- gc-blobs reads every referenced blob path; delete-account erases the user's rows
select lives_ok('select blob_path from public.preset_versions', 'service_role can read preset_versions (gc-blobs)');
select lives_ok($$delete from public.documents where user_id = '11111111-1111-4111-8111-111111111111'$$, 'service_role can delete documents (delete-account)');
select lives_ok($$delete from public.preset_versions where user_id = '11111111-1111-4111-8111-111111111111'$$, 'service_role can delete preset_versions (delete-account)');
select lives_ok($$delete from public.backups where user_id = '11111111-1111-4111-8111-111111111111'$$, 'service_role can delete backups (delete-account)');
select lives_ok($$delete from public.subscriptions where user_id = '11111111-1111-4111-8111-111111111111'$$, 'service_role can delete subscriptions (delete-account)');
reset role;

select * from finish();
rollback;
