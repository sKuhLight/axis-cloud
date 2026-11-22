-- Keep account-only features account-only once Supabase anonymous sign-ins are enabled.
--
-- WHY: editor-cache uploads (20261123120000_editor_cache_uploads.sql) accept Supabase ANONYMOUS sessions — a
-- per-install anonymous auth user, no e-mail, no CAPTCHA — so the project must enable anonymous sign-ins
-- (`[auth] enable_anonymous_sign_ins` in config.toml for the local stack; Dashboard → Authentication → Sign In /
-- Providers on a hosted project). That switch is PROJECT-WIDE: an anonymous user gets a normal JWT with
-- role `authenticated` (plus the claim `is_anonymous: true`), so every policy written `to authenticated` or
-- keyed only on auth.uid() would now also admit a user nobody ever registered — and anonymous users can be
-- minted at will (bounded only by the Auth rate limit per IP). The policies below were written when
-- `authenticated` meant "has an account".
--
-- WHAT: RESTRICTIVE policies (ANDed with every permissive one) that refuse sessions whose JWT says
-- is_anonymous = true, on the account-only surfaces:
--   * documents, preset_versions, backups   cloud sync (no per-user quota on documents; preset quota is per
--                                           user, so unlimited users would mean unlimited storage)
--   * storage.objects, bucket preset-blobs  preset blob uploads (scoped to that bucket by its condition, so
--                                           every other bucket is unaffected)
--   * realtime.messages                     the Remote relay channel (remote:<uid>)
-- Restrictive policies under NEW names (instead of ALTER POLICY on the existing ones) so this works on projects
-- whose original policy names differ, and so the existing policies stay untouched. A token without the claim
-- (issued before anonymous sign-ins existed) is treated as an account: `is not true` lets null through.
-- The service role bypasses RLS and is unaffected.
--
-- VERIFIED, deliberately unchanged (anonymous sessions are harmless or intended there):
--   * subscriptions "own subscription readable" — an anonymous user can only read its own (non-existent) row.
--   * tier_limits "tier limits are public" — public limits, read-only.
--   * device_profiles "device profiles are public" — public read for everyone anyway; WRITES go through the
--     device-profiles edge function, which now refuses anonymous sessions itself (403 account-required).
--   * debug-reports bucket insert policy — already `to anon, authenticated` (insert-only, keyed by the
--     telemetry instance id); an anonymous session gains nothing a signed-out client did not have.
--   * diagnostic_captures, editor_cache_* — no client policy at all (service role only).
--   * preset_quota() / is_paid(uuid) — readouts; an anonymous user sees its own empty numbers. is_paid(uuid)
--     needs another user's uuid, which no Data API role can learn (device_profiles.created_by is withheld).
-- Edge functions (not SQL, listed for completeness): diagnostic-captures already refuses anonymous sessions;
-- delete-account accepts them on purpose (an anonymous uploader must be able to erase itself); gc-blobs is
-- secret-gated; editor-caches accepts them by design.

-- ── cloud sync tables ──
drop policy if exists "documents: no anonymous sessions" on public.documents;
create policy "documents: no anonymous sessions" on public.documents
  as restrictive for all to authenticated
  using ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true)
  with check ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true);

drop policy if exists "preset_versions: no anonymous sessions" on public.preset_versions;
create policy "preset_versions: no anonymous sessions" on public.preset_versions
  as restrictive for all to authenticated
  using ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true)
  with check ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true);

drop policy if exists "backups: no anonymous sessions" on public.backups;
create policy "backups: no anonymous sessions" on public.backups
  as restrictive for all to authenticated
  using ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true)
  with check ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true);

-- ── preset blobs (Storage) — only this bucket: the condition is true for every other bucket ──
drop policy if exists "preset-blobs: no anonymous sessions" on storage.objects;
create policy "preset-blobs: no anonymous sessions" on storage.objects
  as restrictive for all to authenticated
  using (bucket_id <> 'preset-blobs' or (select (auth.jwt() ->> 'is_anonymous')::boolean) is not true)
  with check (bucket_id <> 'preset-blobs' or (select (auth.jwt() ->> 'is_anonymous')::boolean) is not true);

-- ── Remote relay (Realtime private channels) ──
drop policy if exists "axis remote channel: no anonymous sessions" on realtime.messages;
create policy "axis remote channel: no anonymous sessions" on realtime.messages
  as restrictive for all to authenticated
  using ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true)
  with check ((select (auth.jwt() ->> 'is_anonymous')::boolean) is not true);
