-- Free-tier preset sync quotas (0.7.1-beta). Preset sync opens to every registered user; free-tier
-- limits are enforced server-side as a BACKSTOP (the client pre-flights and prunes first — see
-- ForgeFX cloud.ts syncVersions):
--
--   · hard storage cap  — sum of `stored` over DISTINCT blob_path (blobs are content-addressed and
--                         shared across versions; a naive sum would overcount)
--   · 1 retained full-device backup  — a new backup group is admitted only after the old group's
--                         rows are deleted (forces the client's delete-old-first ordering)
--   · N total snapshots — everything with source <> 'backup' (manual AND future 'auto')
--
-- Paid users (subscriptions.active within period) bypass all checks. Limits live in `tier_limits`
-- as data, so they can be tuned without redeploying clients. Enforcement is metadata-gated: a blob
-- uploaded without a surviving preset_versions row is invisible (nothing references it) and bounded
-- by the bucket's file_size_limit; the gc-blobs edge function sweeps such orphans after 24 h.

-- ── tier limits (data, not code) ──
create table if not exists public.tier_limits (
  tier             text primary key,     -- 'free' (a paid tier has no row ⇒ unlimited)
  max_stored_bytes bigint not null,
  max_snapshots    int    not null,
  max_backups      int    not null
);
insert into public.tier_limits (tier, max_stored_bytes, max_snapshots, max_backups)
  values ('free', 3145728, 5, 1)         -- 3 MiB · 5 snapshots · 1 full backup
  on conflict (tier) do update set
    max_stored_bytes = excluded.max_stored_bytes,
    max_snapshots    = excluded.max_snapshots,
    max_backups      = excluded.max_backups;
alter table public.tier_limits enable row level security;
create policy "tier limits are public" on public.tier_limits
  for select to authenticated using (true);

-- ── paid check (security definer: reads the service-role-written subscriptions row, honoring the
--    period end — mirrors ForgeFX cloud.ts #subscription()) ──
create or replace function public.is_paid(uid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select active and (current_period_end is null or current_period_end > now())
                   from subscriptions where user_id = uid), false);
$$;

-- ── quota backstop: reject free-tier inserts that would exceed the limits ──
create or replace function public.enforce_preset_quota() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  lim  tier_limits%rowtype;
  used bigint;
  n    int;
begin
  if public.is_paid(new.user_id) then return new; end if;
  -- serialize per-user: two devices racing must not both pass the count under the cap
  perform pg_advisory_xact_lock(hashtext('pv-quota:' || new.user_id::text));
  select * into lim from tier_limits where tier = 'free';
  if not found then return new; end if;   -- no free limits configured ⇒ unlimited

  -- storage: sum DISTINCT blobs only, excluding the incoming one (re-referencing an existing blob
  -- costs nothing — that's the content-address dedup working as intended)
  select coalesce(sum(b.stored), 0) into used from (
    select distinct on (blob_path) stored from preset_versions
    where user_id = new.user_id and blob_path <> new.blob_path
  ) b;
  if used + new.stored > lim.max_stored_bytes then
    raise exception 'quota:storage';
  end if;

  if new.source = 'backup' then
    select count(distinct backup_id) into n from preset_versions
      where user_id = new.user_id and source = 'backup'
        and backup_id is distinct from new.backup_id;
    if n >= lim.max_backups then
      raise exception 'quota:backups';    -- old group must be deleted before the new one lands
    end if;
  else
    select count(*) into n from preset_versions
      where user_id = new.user_id and source <> 'backup' and id <> new.id;
    if n >= lim.max_snapshots then
      raise exception 'quota:snapshots';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists preset_quota on public.preset_versions;
create trigger preset_quota
  before insert or update of stored, blob_path, source
  on public.preset_versions
  for each row execute function public.enforce_preset_quota();

-- ── quota readout for the UI (invoker rights — RLS scopes every subquery to the caller) ──
create or replace function public.preset_quota() returns json
language sql stable security invoker set search_path = public as $$
  select json_build_object(
    'paid', public.is_paid(auth.uid()),
    'usedBytes', (select coalesce(sum(stored), 0) from (
        select distinct on (blob_path) stored from preset_versions where user_id = auth.uid()) b),
    'snapshots', (select count(*) from preset_versions where user_id = auth.uid() and source <> 'backup'),
    'backups',   (select count(distinct backup_id) from preset_versions where user_id = auth.uid() and source = 'backup'),
    'limits',    (select row_to_json(t) from tier_limits t where tier = 'free')
  );
$$;

-- ── backstop: cap single-object size in the blobs bucket (compressed presets are ~5–25 KB; this
--    bounds orphan-blob abuse without touching legitimate uploads) ──
update storage.buckets set file_size_limit = 524288 where id = 'preset-blobs';
