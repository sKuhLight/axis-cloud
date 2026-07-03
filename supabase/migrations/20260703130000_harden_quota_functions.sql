-- Lock down the quota functions flagged by the security advisor:
--   · enforce_preset_quota — trigger-only; EXECUTE is checked at CREATE TRIGGER time, not at fire
--     time, so no role needs (or should have) RPC access to it.
--   · is_paid — needed by the invoker-rights preset_quota() (authenticated), but anon has no business
--     probing subscription state.
revoke execute on function public.enforce_preset_quota() from public, anon, authenticated;
revoke execute on function public.is_paid(uuid) from public, anon;
revoke execute on function public.preset_quota() from public, anon;
