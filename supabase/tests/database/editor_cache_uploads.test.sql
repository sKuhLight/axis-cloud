-- pgTAP tests for the editor-cache upload data model (20261123120000_editor_cache_uploads.sql): bucket settings,
-- the deny-by-default access model, the reserve function (own/cross-uploader dedup, refresh/recreate of pending
-- rows, coverage gate, per-firmware limit, uploader and network rate limits and byte quotas incl. the pending
-- charge, counters that outlive deleted uploads), the complete function (version-matched distinct uploaders only,
-- high-water mark, covered at 2, closed stays closed, maintainer reopen), constraints and the account cascade.
--
-- Run against a LOCAL stack only (it needs the migrations applied and creates throw-away users inside a
-- transaction that is rolled back):
--   npx --yes supabase@latest start
--   npx --yes supabase@latest db reset
--   npx --yes supabase@latest test db
-- NB: now() is constant inside the transaction, so every row created here has the same created_at; tests that
-- need age set created_at explicitly.
begin;
create extension if not exists pgtap with schema extensions;

select plan(107);

insert into auth.users (id, email) values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'ec-a@example.test'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', 'ec-b@example.test'),
  ('cccccccc-cccc-4ccc-8ccc-cccccccccccc', 'ec-c@example.test'),
  ('dddddddd-dddd-4ddd-8ddd-dddddddddddd', 'ec-d@example.test'),
  ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', 'ec-e@example.test'),
  ('ffffffff-ffff-4fff-8fff-ffffffffffff', 'ec-f@example.test');
insert into auth.users (id, email)
  select ('00000000-0000-4000-8000-' || lpad(g::text, 12, '0'))::uuid, 'ec-n' || g || '@example.test'
    from generate_series(1, 10) g;

-- helpers (session-local)
create function pg_temp.sha(n integer) returns text language sql immutable
  as $$ select lpad(to_hex(n), 64, '0') $$;
create function pg_temp.ipk(n integer) returns text language sql immutable
  as $$ select lpad(to_hex(n), 64, 'e') $$;
create function pg_temp.n(i integer) returns uuid language sql immutable
  as $$ select ('00000000-0000-4000-8000-' || lpad(i::text, 12, '0'))::uuid $$;
-- every uploader gets its own network key unless one is passed
create function pg_temp.netof(u uuid) returns text language sql immutable
  as $$ select encode(sha256(convert_to(u::text, 'UTF8')), 'hex') $$;
create function pg_temp.res(
  p_user     uuid,
  p_sha      text,
  p_ip       text    default null,
  p_fw       text    default '13.0',
  p_file     text    default '13.0',
  p_bytes    integer default 1000,
  p_quota    bigint  default 20971520,
  p_ip_quota bigint  default 20971520
) returns table (row_id uuid, row_status text, deduped boolean) language sql as $$
  select * from public.reserve_editor_cache_upload(
    p_user, coalesce(p_ip, pg_temp.netof(p_user)), 17, p_fw, p_file, null::text,
    'effectDefinitions_11_' || replace(p_file, '.', 'p') || '.cache',
    p_sha, p_bytes, '{"version":1,"tables":2,"names":3}'::jsonb, '{}'::jsonb, '{}'::jsonb, now(), 1,
    p_quota_bytes => p_quota, p_ip_quota_bytes => p_ip_quota)
$$;
create function pg_temp.idof(u uuid, s text) returns uuid language sql stable
  as $$ select id from public.editor_cache_uploads where user_id = u and sha256 = s $$;

-- ── bucket (3) ──
select is((select public from storage.buckets where id = 'editor-caches'), false, 'bucket is private');
select is((select file_size_limit from storage.buckets where id = 'editor-caches'), 4194304::bigint, 'bucket caps objects at 4 MiB');
select is((select allowed_mime_types from storage.buckets where id = 'editor-caches'), array['application/octet-stream'], 'bucket accepts application/octet-stream only');

-- ── functions: service role only (9) ──
select ok(has_function_privilege(g.r::name, g.f, 'execute') = g.expect, g.r || (case when g.expect then ' can' else ' cannot' end) || ' execute ' || split_part(g.f, '(', 1))
from (values
  ('anon',          'public.reserve_editor_cache_upload(uuid,text,integer,text,text,text,text,text,integer,jsonb,jsonb,jsonb,timestamptz,integer,integer,integer,bigint,integer,bigint,integer,integer,integer,bigint)', false),
  ('authenticated', 'public.reserve_editor_cache_upload(uuid,text,integer,text,text,text,text,text,integer,jsonb,jsonb,jsonb,timestamptz,integer,integer,integer,bigint,integer,bigint,integer,integer,integer,bigint)', false),
  ('service_role',  'public.reserve_editor_cache_upload(uuid,text,integer,text,text,text,text,text,integer,jsonb,jsonb,jsonb,timestamptz,integer,integer,integer,bigint,integer,bigint,integer,integer,integer,bigint)', true),
  ('anon',          'public.complete_editor_cache_upload(uuid,uuid,integer,text,integer)', false),
  ('authenticated', 'public.complete_editor_cache_upload(uuid,uuid,integer,text,integer)', false),
  ('service_role',  'public.complete_editor_cache_upload(uuid,uuid,integer,text,integer)', true),
  ('anon',          'public.set_editor_cache_coverage(integer,text,text)', false),
  ('authenticated', 'public.set_editor_cache_coverage(integer,text,text)', false),
  ('service_role',  'public.set_editor_cache_coverage(integer,text,text)', true)
) as g(r, f, expect);

-- ── tables: closed to clients (6), RLS on (3), reads refused (4), no address column (1) ──
select is(
  (select array_agg(p order by p) from unnest(array['select','insert','update','delete','truncate','references','trigger']) as p
    where has_table_privilege(g.r::name, g.t, p)),
  null::text[], g.r || ' has no privilege on ' || g.t)
from (values
  ('anon', 'public.editor_cache_uploads'), ('authenticated', 'public.editor_cache_uploads'),
  ('anon', 'public.editor_cache_coverage'), ('authenticated', 'public.editor_cache_coverage'),
  ('anon', 'public.editor_cache_ip_usage'), ('authenticated', 'public.editor_cache_ip_usage')
) as g(r, t);

select ok(c.relrowsecurity, c.relname || ' has row level security enabled')
  from pg_class c
 where c.oid in ('public.editor_cache_uploads'::regclass, 'public.editor_cache_coverage'::regclass, 'public.editor_cache_ip_usage'::regclass);

set local role authenticated;
select throws_ok('select * from public.editor_cache_uploads', '42501', null, 'authenticated cannot read editor_cache_uploads');
select throws_ok('select * from public.editor_cache_coverage', '42501', null, 'authenticated cannot read editor_cache_coverage');
select throws_ok('select * from public.editor_cache_ip_usage', '42501', null, 'authenticated cannot read editor_cache_ip_usage');
reset role;
set local role anon;
select throws_ok('select * from public.editor_cache_uploads', '42501', null, 'anon cannot read editor_cache_uploads');
reset role;

select is(
  (select count(*)::integer from information_schema.columns
    where table_schema = 'public' and table_name = 'editor_cache_uploads'
      and column_name ~ '(^|_)(ip|addr|address|instance|email)(_|$)'),
  0, 'editor_cache_uploads has no address, instance or e-mail column');

-- ── reserve: new, dedup (6) ──
select is((select row_status from pg_temp.res('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))), 'pending', 'a new reservation is pending');
select is(
  (select object_path from public.editor_cache_uploads where id = pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))),
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/' || pg_temp.sha(1) || '.cache', 'the object path is <user>/<sha256>.cache');
select is(
  (select count(*)::integer from public.editor_cache_ip_usage
    where upload_id = pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))
      and ip_key = pg_temp.netof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa') and bytes is null),
  1, 'the reservation leaves one network counter (keyed hash, no size yet)');
select is((select deduped from pg_temp.res('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))), true, 'the same file from the same uploader is deduped');
select is((select count(*)::integer from public.editor_cache_uploads where user_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'), 1, 'a dedup inserts no second row');
select is((select count(*)::integer from public.editor_cache_ip_usage where ip_key = pg_temp.netof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')), 1, 'nor a second network counter');

-- ── reserve: refresh while no object, unchanged once it is there (4) ──
select is((select deduped from pg_temp.res('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1), p_bytes => 2000)), true, 'a repeat without an object is deduped');
select is((select bytes from public.editor_cache_uploads where id = pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))), 2000, 'and refreshes the announced size');
insert into storage.objects (bucket_id, name)
  values ('editor-caches', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/' || pg_temp.sha(1) || '.cache');
select is((select deduped from pg_temp.res('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1), p_bytes => 3000)), true, 'a repeat with the object present is deduped too');
select is((select bytes from public.editor_cache_uploads where id = pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))), 2000, 'but the size is not refreshed once the object is there');

-- ── reserve: a pending row older than 20 h is recreated (5) ──
select is((select row_status from pg_temp.res('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(2))), 'pending', 'a second file is reserved');
create temp table old_ids as select pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(2)) as id;
update public.editor_cache_uploads set created_at = now() - interval '19 hours' where id = (select id from old_ids);
select is((select deduped from pg_temp.res('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(2))), true, 'a pending row of 19 h is reused');
select is(pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(2)), (select id from old_ids), 'and keeps its id');
update public.editor_cache_uploads set created_at = now() - interval '21 hours' where id = (select id from old_ids);
select is((select deduped from pg_temp.res('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(2))), false, 'a pending row of 21 h is recreated');
select isnt(pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(2)), (select id from old_ids), 'with a new row id');

-- ── complete (8) ──
select is(
  (select row_status || '/' || covered::text
     from public.complete_editor_cache_upload('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1)), 1500, '13.0')),
  'complete/false', 'completing the first upload of a firmware does not cover it');
select is(
  (select status || ' ' || bytes || ' ' || content_version from public.editor_cache_uploads where id = pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))),
  'complete 1500 13.0', 'complete records the real size and the verified header version');
select is((select bytes from public.editor_cache_ip_usage where upload_id = pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))), 1500, 'the network counter records the real size');
select is((select contributors from public.editor_cache_coverage where model = 17 and device_firmware = '13.0'), 1, 'one contributor');
select is((select state from public.editor_cache_coverage where model = 17 and device_firmware = '13.0'), 'collecting', 'still collecting');
select is(
  (select row_status from public.complete_editor_cache_upload('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1)), 1500, '13.0')),
  'complete', 'a repeat complete is idempotent');
select is(
  (select count(*)::integer from public.complete_editor_cache_upload('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1)), 1500, '13.0')),
  0, 'another uploader cannot complete it');
select is((select version_match from public.editor_cache_uploads where id = pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(1))), true, 'version_match is generated true when the file version is the device firmware');

-- ── cross-uploader dedup (3) ──
select is((select row_id from pg_temp.res('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', pg_temp.sha(1))), null::uuid, 'an identical file another uploader completed is deduped without a row id');
select is((select row_status from pg_temp.res('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', pg_temp.sha(1))), 'complete', 'and reported complete');
select is((select count(*)::integer from public.editor_cache_uploads where user_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'), 0, 'no row is stored for it');

-- ── coverage: distinct uploaders only (5) ──
select lives_ok(
  $$select * from public.complete_editor_cache_upload('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.idof('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', pg_temp.sha(2)), 1000, '13.0')$$,
  'the same uploader completes a second file of the firmware');
select is((select contributors from public.editor_cache_coverage where model = 17 and device_firmware = '13.0'), 1, 'which does not add a contributor');
select lives_ok($$select * from pg_temp.res('cccccccc-cccc-4ccc-8ccc-cccccccccccc', pg_temp.sha(3))$$, 'a second uploader reserves its own file');
select is(
  (select row_status || '/' || covered::text
     from public.complete_editor_cache_upload('cccccccc-cccc-4ccc-8ccc-cccccccccccc', pg_temp.idof('cccccccc-cccc-4ccc-8ccc-cccccccccccc', pg_temp.sha(3)), 1000, '13.0')),
  'complete/true', 'a second distinct uploader covers the firmware');
select is(
  (select state || ' ' || contributors from public.editor_cache_coverage where model = 17 and device_firmware = '13.0'),
  'covered 2', 'coverage is covered with 2 contributors');

-- ── coverage gate: covered and closed refuse new reservations (3) ──
select throws_ok($$select * from pg_temp.res('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(4))$$,
  'XQ003', 'editor_cache_not_wanted', 'a covered firmware is not wanted');
select lives_ok($$select public.set_editor_cache_coverage(17, '12.0', 'closed')$$, 'the maintainer closes a firmware');
select throws_ok($$select * from pg_temp.res('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(5), p_fw => '12.0', p_file => '12.0')$$,
  'XQ003', 'editor_cache_not_wanted', 'a closed firmware is not wanted');

-- ── a version-mismatched upload never counts (4) ──
select lives_ok($$select * from pg_temp.res('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(6), p_fw => '13.1', p_file => '12.0')$$,
  'a file whose version differs from the device firmware is reserved');
select is((select version_match from public.editor_cache_uploads where id = pg_temp.idof('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(6))), false, 'version_match is false for it');
select lives_ok(
  $$select * from public.complete_editor_cache_upload('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.idof('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(6)), 1000, '12.0')$$,
  'and completed');
select is((select count(*)::integer from public.editor_cache_coverage where model = 17 and device_firmware = '13.1'), 0, 'but it does not count toward coverage');

-- ── maintainer reopen: only uploads after the reopen count (7) ──
update public.editor_cache_uploads set created_at = now() - interval '2 days'
 where model = 17 and device_firmware = '13.0';
select lives_ok($$select public.set_editor_cache_coverage(17, '13.0', 'collecting')$$, 'the maintainer reopens a covered firmware');
select is(
  (select state || ' ' || contributors || ' ' || (reopened_at is not null)::text from public.editor_cache_coverage where model = 17 and device_firmware = '13.0'),
  'collecting 0 true', 'reopen resets the contributors and records when');
select lives_ok($$select * from pg_temp.res('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', pg_temp.sha(7))$$, 'a new uploader reserves after the reopen');
select is(
  (select row_status || '/' || covered::text
     from public.complete_editor_cache_upload('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', pg_temp.idof('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', pg_temp.sha(7)), 1000, '13.0')),
  'complete/false', 'the uploads from before the reopen do not re-cover it');
select is((select contributors from public.editor_cache_coverage where model = 17 and device_firmware = '13.0'), 1, 'one contributor since the reopen');
select lives_ok($$select * from pg_temp.res('ffffffff-ffff-4fff-8fff-ffffffffffff', pg_temp.sha(8))$$, 'another new uploader reserves');
select is(
  (select row_status || '/' || covered::text
     from public.complete_editor_cache_upload('ffffffff-ffff-4fff-8fff-ffffffffffff', pg_temp.idof('ffffffff-ffff-4fff-8fff-ffffffffffff', pg_temp.sha(8)), 1000, '13.0')),
  'complete/true', 'two distinct uploaders after the reopen cover it again');

-- ── one network counts once: two uploaders behind one network key cannot cover a firmware (5) ──
select lives_ok($$select * from pg_temp.res(pg_temp.n(9), pg_temp.sha(109), p_ip => pg_temp.ipk(9), p_fw => '50.0', p_file => '50.0')$$,
  'an uploader on network 9 reserves');
select lives_ok(
  $$select * from public.complete_editor_cache_upload(pg_temp.n(9), pg_temp.idof(pg_temp.n(9), pg_temp.sha(109)), 1000, '50.0')$$,
  'and completes');
select lives_ok($$select * from pg_temp.res(pg_temp.n(10), pg_temp.sha(110), p_ip => pg_temp.ipk(9), p_fw => '50.0', p_file => '50.0')$$,
  'a second uploader on the SAME network reserves another file');
select is(
  (select row_status || '/' || covered::text
     from public.complete_editor_cache_upload(pg_temp.n(10), pg_temp.idof(pg_temp.n(10), pg_temp.sha(110)), 1000, '50.0')),
  'complete/false', 'two uploaders behind one network key do not cover the firmware');
select is((select contributors from public.editor_cache_coverage where model = 17 and device_firmware = '50.0'), 1,
  'contributors = least(distinct uploaders, distinct networks)');

-- ── a refresh is judged by the STORED row's model/firmware, not the repeat request's claim (5) ──
select lives_ok($$select * from pg_temp.res('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', pg_temp.sha(40), p_fw => '40.0', p_file => '40.0')$$,
  'an upload for firmware 40.0 is reserved (no object yet)');
select lives_ok($$select public.set_editor_cache_coverage(17, '41.0', 'covered')$$, 'another firmware (41.0) is covered');
select is((select deduped from pg_temp.res('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', pg_temp.sha(40), p_fw => '41.0', p_file => '41.0')), true,
  'a repeat claiming the covered 41.0 is still a refresh of the 40.0 upload');
select lives_ok($$select public.set_editor_cache_coverage(17, '40.0', 'covered')$$, 'now 40.0 is covered too');
select throws_ok($$select * from pg_temp.res('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', pg_temp.sha(40), p_fw => '42.0', p_file => '42.0')$$,
  'XQ003', 'editor_cache_not_wanted', 'and a repeat claiming an uncovered 42.0 cannot dodge that');

-- ── set_editor_cache_coverage normalizes the firmware like devices report it (2) ──
select is((select device_firmware from public.set_editor_cache_coverage(16, '032.06', 'covered')), '32.6', '''032.06'' is stored as ''32.6''');
select throws_ok($$select public.set_editor_cache_coverage(16, '32', 'covered')$$, '22023', null, 'a firmware without a minor part is refused');

-- ── per (uploader, model, firmware) limit (2) and uploader rate limit (2) ──
select lives_ok(
  $$select pg_temp.res('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', pg_temp.sha(9 + g), p_fw => '14.0', p_file => '14.0') from generate_series(1, 2) g$$,
  'two uploads for one firmware are admitted');
select throws_ok($$select * from pg_temp.res('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', pg_temp.sha(12), p_fw => '14.0', p_file => '14.0')$$,
  'XQ004', 'editor_cache_firmware_limit', 'the third upload for the same firmware is refused');
select lives_ok(
  $$select pg_temp.res('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', pg_temp.sha(12 + g), p_fw => g || '.0', p_file => g || '.0') from generate_series(15, 17) g$$,
  'uploads 3..5 inside the hour are admitted');
select throws_ok($$select * from pg_temp.res('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', pg_temp.sha(30), p_fw => '18.0', p_file => '18.0')$$,
  'XQ001', 'editor_cache_rate_limited', 'the sixth upload inside the window is refused');

-- ── uploader byte quota, pending charged at the 4 MiB cap (3) ──
select lives_ok($$select * from pg_temp.res('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(20), p_fw => '20.0', p_file => '20.0', p_quota => 4194804)$$,
  'a reservation under the quota is admitted');
select throws_ok($$select * from pg_temp.res('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(21), p_fw => '21.0', p_file => '21.0', p_quota => 4194804)$$,
  'XQ002', 'editor_cache_quota_exceeded', 'the next one is refused: the unconfirmed reservation counts at the cap');
update public.editor_cache_uploads set status = 'complete', bytes = 1000
 where id = pg_temp.idof('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(20));
select lives_ok($$select * from pg_temp.res('dddddddd-dddd-4ddd-8ddd-dddddddddddd', pg_temp.sha(21), p_fw => '21.0', p_file => '21.0', p_quota => 4194804)$$,
  'completing the small upload frees its charge');

-- ── network rate limit: fresh uploader ids do not help; counters outlive deleted uploads (4) ──
select lives_ok(
  $$select pg_temp.res(pg_temp.n(g), pg_temp.sha(100 + g), p_ip => pg_temp.ipk(1)) from generate_series(1, 5) g$$,
  'five uploaders on one network are admitted');
select throws_ok($$select * from pg_temp.res(pg_temp.n(6), pg_temp.sha(106), p_ip => pg_temp.ipk(1))$$,
  'XQ005', 'editor_cache_network_rate_limited', 'a sixth uploader on the same network is refused');
delete from public.editor_cache_uploads where user_id = pg_temp.n(1);
select is((select count(*)::integer from public.editor_cache_ip_usage where ip_key = pg_temp.ipk(1) and upload_id is null), 1,
  'deleting an upload unlinks its counter but keeps it');
select throws_ok($$select * from pg_temp.res(pg_temp.n(6), pg_temp.sha(106), p_ip => pg_temp.ipk(1))$$,
  'XQ005', 'editor_cache_network_rate_limited', 'so delete-and-retry does not reset the network limit');

-- ── network byte quota (3) ──
select lives_ok($$select * from pg_temp.res(pg_temp.n(7), pg_temp.sha(107), p_ip => pg_temp.ipk(2), p_ip_quota => 4194804)$$,
  'a reservation under the network quota is admitted');
select throws_ok($$select * from pg_temp.res(pg_temp.n(8), pg_temp.sha(108), p_ip => pg_temp.ipk(2), p_ip_quota => 4194804)$$,
  'XQ006', 'editor_cache_network_quota_exceeded', 'another uploader on that network exceeds it (pending counts at the cap)');
delete from public.editor_cache_uploads where user_id = pg_temp.n(7);
select lives_ok($$select * from pg_temp.res(pg_temp.n(8), pg_temp.sha(108), p_ip => pg_temp.ipk(2), p_ip_quota => 4194804)$$,
  'a pending upload deleted before it completed no longer counts');

-- ── argument checks (2) ──
select throws_ok(
  $$select * from public.reserve_editor_cache_upload('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '203.0.113.7', 17, '13.0', '13.0', null,
      'effectDefinitions_11_13p0.cache', pg_temp.sha(99), 10, '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, now(), 1)$$,
  '22023', null, 'a network key that is not a 64-hex hash (e.g. a raw address) is refused');
select throws_ok($$select public.set_editor_cache_coverage(17, '13.0', 'bogus')$$, '22023', null, 'set_editor_cache_coverage refuses an unknown state');

-- ── constraints (6) ──
select throws_ok(
  $$insert into public.editor_cache_uploads (user_id, model, device_firmware, file_version, file_name, sha256, bytes, consent_at, consent_version, object_path)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, '13.0', '13.0', 'x.cache', pg_temp.sha(200), 10, now(), 1, 'someone-else/x.cache')$$,
  '23514', null, 'object_path must be <user_id>/<sha256>.cache');
select throws_ok(
  $$insert into public.editor_cache_uploads (user_id, model, device_firmware, file_version, file_name, sha256, bytes, consent_at, consent_version, object_path, status)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, '13.0', '13.0', 'x.cache', pg_temp.sha(201), 10, now(), 1, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/' || pg_temp.sha(201) || '.cache', 'bogus')$$,
  '23514', null, 'status must be pending or complete');
select throws_ok(
  $$insert into public.editor_cache_uploads (user_id, model, device_firmware, file_version, file_name, sha256, bytes, consent_at, consent_version, object_path)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, 'v13', '13.0', 'x.cache', pg_temp.sha(202), 10, now(), 1, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/' || pg_temp.sha(202) || '.cache')$$,
  '23514', null, 'device_firmware must look like 13.0');
select throws_ok(
  $$insert into public.editor_cache_uploads (user_id, model, device_firmware, file_version, file_name, sha256, bytes, consent_at, consent_version, object_path)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, '13.0', '13.0', 'x.cache', upper(pg_temp.sha(203)), 10, now(), 1, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/' || upper(pg_temp.sha(203)) || '.cache')$$,
  '23514', null, 'sha256 must be lowercase hex');
select throws_ok(
  $$insert into public.editor_cache_uploads (user_id, model, device_firmware, file_version, file_name, sha256, bytes, consent_at, consent_version, object_path)
    values ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 17, '13.0', '13.0', 'x.cache', pg_temp.sha(204), 4194305, now(), 1, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/' || pg_temp.sha(204) || '.cache')$$,
  '23514', null, 'bytes must not exceed 4 MiB');
select throws_ok(
  $$insert into public.editor_cache_coverage (model, device_firmware, state) values (17, '99.0', 'done')$$,
  '23514', null, 'coverage state must be collecting, covered or closed');

-- ── account deletion cascades; network counters stay, unlinked (2) ──
delete from auth.users where id = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
select is((select count(*)::integer from public.editor_cache_uploads where user_id = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'), 0, 'deleting the auth user removes its upload rows');
select is((select count(*)::integer from public.editor_cache_ip_usage where ip_key = pg_temp.netof('cccccccc-cccc-4ccc-8ccc-cccccccccccc') and upload_id is null), 1,
  'its network counter remains, carrying no link to the user');

select * from finish();
rollback;
