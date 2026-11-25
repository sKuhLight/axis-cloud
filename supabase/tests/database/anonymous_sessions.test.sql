-- pgTAP tests for 20261123130000_anonymous_session_hardening.sql: with Supabase anonymous sign-ins enabled
-- (needed for editor-cache uploads), an anonymous session — role `authenticated`, JWT claim is_anonymous = true —
-- must not reach the account-only surfaces: cloud-sync tables, the preset-blobs bucket, the Remote relay channel.
-- Accounts (claim false, or tokens without the claim) are unaffected.
--
-- Storage and Realtime are checked through their policy definitions (pg_policies): inserting into
-- storage.objects / realtime.messages as a client role also runs those services' own triggers and partitions,
-- which this test should not depend on. The tables are checked by behaviour.
--
-- Run against a LOCAL stack only:
--   npx --yes supabase@latest start
--   npx --yes supabase@latest db reset
--   npx --yes supabase@latest test db
begin;
create extension if not exists pgtap with schema extensions;

select plan(13);

insert into auth.users (id, email) values
  ('a0000000-0000-4000-8000-00000000000a', null),
  ('b0000000-0000-4000-8000-00000000000b', 'anon-test-account@example.test');

-- ── the restrictive policies exist (5) ──
select is(
  (select permissive || ' ' || array_to_string(roles, ',') || ' ' || cmd from pg_policies
    where schemaname = g.s and tablename = g.t and policyname = g.p),
  'RESTRICTIVE authenticated ALL', g.s || '.' || g.t || ' has the restrictive policy "' || g.p || '"')
from (values
  ('public',   'documents',       'documents: no anonymous sessions'),
  ('public',   'preset_versions', 'preset_versions: no anonymous sessions'),
  ('public',   'backups',         'backups: no anonymous sessions'),
  ('storage',  'objects',         'preset-blobs: no anonymous sessions'),
  ('realtime', 'messages',        'axis remote channel: no anonymous sessions')
) as g(s, t, p);

-- ── the storage policy is scoped to preset-blobs only (1) ──
select ok(
  (select qual like '%preset-blobs%' and with_check like '%preset-blobs%' from pg_policies
    where schemaname = 'storage' and tablename = 'objects' and policyname = 'preset-blobs: no anonymous sessions'),
  'the storage policy only constrains the preset-blobs bucket');

-- ── an anonymous session cannot use cloud sync (4) ──
set local role authenticated;
set local request.jwt.claims = '{"sub":"a0000000-0000-4000-8000-00000000000a","role":"authenticated","is_anonymous":true}';
set local request.jwt.claim.sub = 'a0000000-0000-4000-8000-00000000000a';
select throws_ok(
  $$insert into public.documents (user_id, collection, id, data, updated_at)
    values ('a0000000-0000-4000-8000-00000000000a', 'config', 'k', '{}'::jsonb, 1)$$,
  '42501', null, 'an anonymous session cannot write cloud-sync documents');
select throws_ok(
  $$insert into public.preset_versions (user_id, id, location, crc, name, model, captured_at, source, bytes, stored, blob_path)
    values ('a0000000-0000-4000-8000-00000000000a', 'v1', 0, 1, 'n', 'FM3', 1, 'manual', 10, 10, 'a0000000-0000-4000-8000-00000000000a/blobs/x.br')$$,
  '42501', null, 'an anonymous session cannot write preset versions');
select throws_ok(
  $$insert into public.backups (user_id, id, created_at) values ('a0000000-0000-4000-8000-00000000000a', 'b1', 1)$$,
  '42501', null, 'an anonymous session cannot write backups');
reset role;

-- a row that exists for the anonymous user (written by the owner) stays invisible to the anonymous session
insert into public.documents (user_id, collection, id, data, updated_at)
  values ('a0000000-0000-4000-8000-00000000000a', 'config', 'k', '{}'::jsonb, 1);
set local role authenticated;
set local request.jwt.claims = '{"sub":"a0000000-0000-4000-8000-00000000000a","role":"authenticated","is_anonymous":true}';
set local request.jwt.claim.sub = 'a0000000-0000-4000-8000-00000000000a';
select is((select count(*)::integer from public.documents), 0, 'an anonymous session reads no documents, not even its own');
reset role;

-- ── accounts are unaffected: claim false, and tokens without the claim (3) ──
set local role authenticated;
set local request.jwt.claims = '{"sub":"b0000000-0000-4000-8000-00000000000b","role":"authenticated","is_anonymous":false}';
set local request.jwt.claim.sub = 'b0000000-0000-4000-8000-00000000000b';
select lives_ok(
  $$insert into public.documents (user_id, collection, id, data, updated_at)
    values ('b0000000-0000-4000-8000-00000000000b', 'config', 'k2', '{}'::jsonb, 1)$$,
  'an account session still writes its documents');
select is((select count(*)::integer from public.documents), 1, 'and reads them');
set local request.jwt.claims = '{"sub":"b0000000-0000-4000-8000-00000000000b","role":"authenticated"}';
select lives_ok($$update public.documents set rev = 2 where id = 'k2'$$, 'a token without the is_anonymous claim counts as an account');
reset role;

select * from finish();
rollback;
