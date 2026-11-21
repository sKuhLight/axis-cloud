-- pgTAP tests for 20261122120000_subscriptions_source_catchup.sql: public.subscriptions has the nullable
-- `source text` column, however the table was created (init on a fresh stack, or the catch-up migration on
-- a project that predates init's current form), and the table-level grants cover it.
--
-- Run against a LOCAL stack only (it needs the migrations applied and creates a throw-away row inside a
-- transaction that is rolled back):
--   npx --yes supabase@latest start
--   npx --yes supabase@latest db reset
--   npx --yes supabase@latest test db
begin;
create extension if not exists pgtap with schema extensions;

select plan(5);

insert into auth.users (id, email) values
  ('44444444-4444-4444-8444-444444444444', 'subsource@example.test');

-- ── column (3) ──
select has_column('public', 'subscriptions', 'source', 'subscriptions has a source column');
select col_type_is('public', 'subscriptions', 'source', 'text', 'subscriptions.source is text');
select col_is_null('public', 'subscriptions', 'source', 'subscriptions.source is nullable');

-- ── it is writable and readable by the service role (the table-level grants cover it) (2) ──
set local role service_role;
select lives_ok(
  $$insert into public.subscriptions (user_id, active, plan, source)
    values ('44444444-4444-4444-8444-444444444444', true, 'Supporter', 'patreon')$$,
  'service_role can write subscriptions.source');
select is(
  (select source from public.subscriptions where user_id = '44444444-4444-4444-8444-444444444444'),
  'patreon',
  'service_role can read subscriptions.source back');
reset role;

select * from finish();
rollback;
