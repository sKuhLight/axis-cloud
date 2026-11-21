-- Explicit table and function privileges for the Data API roles (anon, authenticated, service_role).
--
-- WHY: every earlier migration relied on IMPLICIT grants. Supabase projects used to run
-- `alter default privileges ... in schema public grant all on tables to anon, authenticated,
-- service_role` (and EXECUTE on functions), so any table/function the `postgres` role created in
-- `public` was reachable from PostgREST without a single GRANT in our SQL. Projects created with the
-- new secure defaults do NOT get that: new tables only receive the non-DML privileges (TRUNCATE,
-- REFERENCES, TRIGGER, and MAINTAIN on PG 17) for the three roles, i.e. no SELECT/INSERT/UPDATE/DELETE,
-- and new functions/sequences are usable by their owner only.
-- On such a project, with only the earlier migrations applied,
--   * every PostgREST call of a signed-in user fails with 42501 "permission denied" before RLS is even
--     evaluated (documents, preset_versions, backups, subscriptions, tier_limits, device_profiles, and
--     rpc preset_quota), and
--   * the edge functions (service role) cannot read or write any table: the service role bypasses RLS
--     but NOT table privileges.
--
-- WHAT: grant exactly what the RLS policies and the real flows use, and nothing more. RLS stays the
-- gate for users; these grants only make the policies reachable. All statements are plain, idempotent
-- GRANTs. On projects created before the default change the same privileges already exist (through the
-- old implicit defaults), so this migration is a no-op there.
--
-- OUT OF SCOPE (follow-ups, deliberately not done here):
--   * Older projects keep their broader implicit grants (all privileges for anon/authenticated/
--     service_role on every public table, EXECUTE on the helper functions). Tightening them needs
--     REVOKEs, which this migration does not issue; do it as a separate, reviewed migration.
--   * The new-project default ACL still hands the non-DML privileges (TRUNCATE, REFERENCES, TRIGGER, ...)
--     on new public tables to the three roles. PostgREST cannot issue TRUNCATE, so this is not reachable through the Data API, but a
--     follow-up could revoke it (and `alter default privileges` so future tables start from zero).
--
-- NOT granted on purpose:
--   * diagnostic_captures: nothing for anon/authenticated (its migration revokes them deliberately; the
--     table is maintainer-only). Do not add any.
--   * enforce_preset_quota(): nobody. It is trigger-only; EXECUTE is checked at CREATE TRIGGER time, not
--     when the trigger fires, so no role needs it (see 20260703130000_harden_quota_functions.sql).
--   * reserve_diagnostic_capture(...): stays service_role only, granted by its own migration.
--   * TRUNCATE for anyone; anything for `public`.

-- ───────────────────────────── authenticated (signed-in users, RLS-scoped) ─────────────────────────────

-- Per-user data behind `for all` policies (`auth.uid() = user_id`, init.sql). ForgeFX sync
-- (ForgeFX server/src/runtime/cloud.ts) selects and upserts (insert + update) `documents` and
-- `preset_versions` and deletes pruned `preset_versions`. `documents` carry a `deleted` tombstone and
-- `backups` is not yet touched by the client; DELETE and the `backups` grants mirror the `for all`
-- policies so a hard delete or a backup-row writer does not hit a privilege wall.
grant select, insert, update, delete on public.documents, public.preset_versions, public.backups to authenticated;

-- Read-only for clients. subscriptions: the client reads its own row (cloud.ts #subscription(); written only
-- by the service role). tier_limits: read by the invoker-rights preset_quota() below (policy "tier limits
-- are public", authenticated only). device_profiles: policy "device profiles are public" (select only; the
-- shared store is written exclusively by the device-profiles edge function).
grant select on public.subscriptions, public.tier_limits, public.device_profiles to authenticated;

-- Quota helpers. preset_quota() is `security invoker` (cloud.ts calls rpc('preset_quota')), so it runs as
-- the caller and needs EXECUTE on itself and on is_paid(), which it calls. is_paid() is security definer
-- and reads the service-role-written subscriptions row. NB: is_paid(uuid) takes an arbitrary uid, so a
-- signed-in user who knows another user's uuid can probe that user's paid state; unchanged from older
-- projects and not widened here.
grant execute on function public.is_paid(uuid) to authenticated, service_role;
grant execute on function public.preset_quota() to authenticated, service_role;

-- ──────────────────────────────────── anon (publishable key, signed out) ────────────────────────────────────

-- The only table anonymous callers may read: the shared, non-sensitive device-profile store (policy
-- "device profiles are public", `to anon, authenticated`). The ForgeFX client goes through the
-- device-profiles edge function (service role) rather than PostgREST, so this only matters for direct
-- Data API readers. Everything else is per-user and unusable without auth.uid(); anon gets nothing there.
-- (The anonymous `debug-reports` upload is a Storage policy on storage.objects, not a table grant.)
grant select on public.device_profiles to anon;

-- ───────────────────── service_role (edge functions + maintainer; bypasses RLS, not privileges) ─────────────────────

-- delete-account (GDPR erase) deletes by `user_id` for these tables; gc-blobs reads preset_versions.blob_path
-- across all users. A DELETE ... WHERE user_id = ... also needs SELECT on the filtered column. The service
-- role never inserts or updates user rows.
grant select, delete on public.documents, public.preset_versions, public.backups to service_role;

-- subscriptions is the service-role-written supporter table (init.sql; "service-role-written" in the quota
-- migration): the planned Patreon link/webhook and manual maintainer grants insert/update it, delete-account
-- removes the user's row. No code in this repo writes it yet; without the grants the documented write path
-- would not work on a new project.
grant select, insert, update, delete on public.subscriptions to service_role;

-- tier_limits is "data, not code": limits are tuned by the maintainer without redeploying clients. No edge
-- function touches it; DELETE is left out (a missing 'free' row means unlimited, so removal is a
-- deliberate dashboard/SQL-editor action).
grant select, insert, update on public.tier_limits to service_role;

-- device-profiles edge function: GET reads (the function uses the service client), POST counts the caller's
-- recent rows for the rate limit and inserts. Profiles are never updated or deleted by the function.
grant select, insert on public.device_profiles to service_role;

-- diagnostic-captures function: finalize reads the row and flips pending -> complete (UPDATE); gc-blobs
-- reads and deletes rows; delete-account deletes by user_id; the maintainer reads and deletes via REST
-- (README "Reading captures"). Rows are CREATED only by reserve_diagnostic_capture() (security definer),
-- so no INSERT here.
grant select, update, delete on public.diagnostic_captures to service_role;
