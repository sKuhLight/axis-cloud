-- pgTAP tests for the diagnostic-captures data model: bucket settings, the atomic reservation function
-- (dedup, rate limit, byte quota), its grants, table constraints and the deny-by-default access model.
--
-- Run against a LOCAL stack only (it needs the migrations applied and creates throw-away users inside a
-- transaction that is rolled back):
--   npx --yes supabase@latest start
--   npx --yes supabase@latest db reset
--   npx --yes supabase@latest test db
begin;
create extension if not exists pgtap with schema extensions;

select plan(20);

insert into auth.users (id, email) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'diag-a@example.test'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'diag-b@example.test'),
  ('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'diag-c@example.test');

-- ── bucket ──
select is((select public from storage.buckets where id = 'diagnostic-captures'), false, 'bucket is private');
select is((select file_size_limit from storage.buckets where id = 'diagnostic-captures'), 26214400::bigint, 'bucket caps objects at 25 MiB');
select is((select allowed_mime_types from storage.buckets where id = 'diagnostic-captures'), array['application/gzip'], 'bucket accepts gzip only');

-- ── grants: the reservation function is service-role only ──
select is(has_function_privilege('anon', 'public.reserve_diagnostic_capture(uuid,text,integer,text,jsonb,text,integer,integer,integer,bigint,integer)', 'execute'), false, 'anon cannot execute reserve_diagnostic_capture');
select is(has_function_privilege('authenticated', 'public.reserve_diagnostic_capture(uuid,text,integer,text,jsonb,text,integer,integer,integer,bigint,integer)', 'execute'), false, 'authenticated cannot execute reserve_diagnostic_capture');
select is(has_function_privilege('service_role', 'public.reserve_diagnostic_capture(uuid,text,integer,text,jsonb,text,integer,integer,integer,bigint,integer)', 'execute'), true, 'service_role can execute reserve_diagnostic_capture');

-- ── reservation: new, dedup ──
select is((select row_status from public.reserve_diagnostic_capture('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cap-1', 17, '12.0', '{}'::jsonb, 'done', 1000)), 'pending', 'a new reservation is pending');
select is((select deduped from public.reserve_diagnostic_capture('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cap-1', 17, '12.0', '{}'::jsonb, 'done', 1000)), true, 'the same capture id is deduped');
select is((select count(*)::integer from public.diagnostic_captures where user_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), 1, 'a dedup inserts no second row');

-- ── rate limit: 5 new captures per rolling hour ──
select lives_ok(
  $$select public.reserve_diagnostic_capture('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cap-' || g, 17, null, '{}'::jsonb, 'done', 1000) from generate_series(2, 5) g$$,
  'reservations 2..5 are admitted');
select throws_ok(
  $$select * from public.reserve_diagnostic_capture('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cap-6', 17, null, '{}'::jsonb, 'done', 1000)$$,
  'XQ001', 'diagnostic_rate_limited', 'the sixth capture inside the window is rejected');
select lives_ok(
  $$select * from public.reserve_diagnostic_capture('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'cap-1', 17, '12.0', '{}'::jsonb, 'done', 1000)$$,
  'a repeat of a known capture is not throttled at the limit');
select lives_ok(
  $$select * from public.reserve_diagnostic_capture('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'cap-1', 17, null, '{}'::jsonb, 'done', 1000)$$,
  'another user is not affected by the limit');

-- ── byte quota: 200 MiB per rolling 30 days (rate limit raised for this check) ──
select lives_ok(
  $$select public.reserve_diagnostic_capture('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'big-' || g, 17, null, '{}'::jsonb, 'done', 26214400, 100) from generate_series(1, 8) g$$,
  'eight 25 MiB reservations fit the 200 MiB quota exactly');
select throws_ok(
  $$select * from public.reserve_diagnostic_capture('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'big-9', 17, null, '{}'::jsonb, 'done', 1, 100)$$,
  'XQ002', 'diagnostic_quota_exceeded', 'the next byte over the quota is rejected');

-- ── table constraints ──
select throws_ok(
  $$insert into public.diagnostic_captures (user_id, capture_id, model, state, bytes, object_path, status)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'x1', 17, 'done', 10, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/x1.json.gz', 'bogus')$$,
  '23514', null, 'status must be pending or complete');
select throws_ok(
  $$insert into public.diagnostic_captures (user_id, capture_id, model, state, bytes, object_path)
    values ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'x2', 17, 'done', 10, 'someone-else/x2.json.gz')$$,
  '23514', null, 'object_path must be <user_id>/<capture_id>.json.gz');

-- ── access model: no client can read the table ──
set local role authenticated;
select throws_ok('select * from public.diagnostic_captures', '42501', null, 'authenticated cannot read diagnostic_captures');
reset role;
set local role anon;
select throws_ok('select * from public.diagnostic_captures', '42501', null, 'anon cannot read diagnostic_captures');
reset role;

-- ── account deletion cascades ──
delete from auth.users where id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
select is((select count(*)::integer from public.diagnostic_captures where user_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), 0, 'deleting the auth user removes its capture rows');

select * from finish();
rollback;
