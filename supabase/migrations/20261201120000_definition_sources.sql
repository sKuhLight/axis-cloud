-- Shared device definitions (cloud v2): a PUBLIC store of sanitized raw definition sources, one row per
-- (model, firmware, kind, fact hash), with tiers, a server-side ranking per kind, private contribution links and
-- private spot-check reports. The `definition-sources` edge function validates and sanitizes a contribution,
-- computes its fact hash / summary / quality / coverage score (never trusted from the client) and then calls the
-- functions below with the service role. Clients never write here directly.
--
-- Objects:
--   * definition_sources               PUBLIC content (sanitized raw source + server-computed numbers). No user
--                                      link: only counts and DAY-granular dates. Readable by everyone (column-level
--                                      grant + RLS hides `rejected`, `quarantined` and orphaned rows).
--   * definition_source_contributions  PRIVATE: who shared which source (auth user id — account or anonymous
--                                      session — and a keyed hash of the network, never the address). One vote per
--                                      uploader and (model, firmware, kind). Unlinked after 180 days (user id and
--                                      network key nulled, app stamps cleared, consent time coarsened to the day);
--                                      the row and the counts it makes stay.
--   * definition_source_reports        PRIVATE: spot-check outcomes (one per source and uploader), 180 days.
--   * definition_source_network_usage  PRIVATE: per-network usage counters for the network limits (keyed hash +
--                                      action + bytes, NO user id), 30 days. They outlive withdrawals, so
--                                      withdraw-and-retry (or replacing one's vote over and over) cannot reset the
--                                      network limits — anonymous uploader ids are free to mint, so these are the
--                                      limits that bind an abuser (same reasoning as editor_cache_ip_usage).
--
-- Ranking (select_definition_sources): best row PER KIND, never across kinds (an editor-cache source never
-- competes with a live read), by tier (official, verified, candidate) -> quality -> coverage score -> contributors
-- -> networks -> OLDEST first. The date never makes a row win: a newer row only displaces an older one by being
-- better. `rejected`, `quarantined` and orphaned rows (no contribution, not pinned) are never served.
--
-- Tiers: `official` / `rejected` are maintainer decisions (`pinned = true`, enforced by a check), sticky and kept
-- even without contributions. `verified` = quality 3 AND at least 2 contributors AND 2 networks with the identical
-- fact hash (thresholds live in definition_source_refresh only, so every path applies the same rule). A lossy read
-- (quality <= 2) is never auto-verified, so it can never outrank a complete read of its kind through the tier.
-- Everything else is `candidate`. `quarantined` is derived (generated column): a non-pinned `candidate` with
-- failure reports from >= 3 networks and more failures than passes. Verified/official rows are never
-- auto-quarantined; passes or a maintainer pin lift it. Contributing facts the maintainer `rejected` is refused.
--
-- Access model: definition_sources is public-read through a column-level grant plus RLS; the three private
-- tables have RLS on with NO policy and no privileges for anon/authenticated. All writes go through the SECURITY
-- DEFINER functions below (EXECUTE for service_role only); the internal helpers are executable by nobody. The
-- service role bypasses RLS: the edge function's `GET /source/<id>` must apply the policy's filter itself
-- (tier <> 'rejected' and not quarantined and (pinned or contributors > 0)).
--
-- Locks (advisory, two-key form so they cannot collide with other lock keys; always taken in this order):
-- uploader -> network -> source key (model, firmware, kind). The source-key lock serializes creating a source,
-- moving a vote and deleting an orphan of that key, so a concurrent contribution never references a source that
-- is being deleted. Withdraw and the orphan cleanup take several source keys in (model, firmware, kind) order.
-- ACCOUNT DELETION (delete-account) must call withdraw_definition_contributions(<uid>) BEFORE deleting the auth
-- user: that takes the source keys sorted and deletes the orphans at once. The auth.users cascade stays only as a
-- fallback — its delete trigger takes source keys in delete order (deadlock-prone against a concurrent withdraw or
-- cleanup; Postgres then aborts one side) and leaves orphans for cleanup_orphan_definition_sources().
--
-- Errors (SQLSTATE; limits carry the retry seconds in DETAIL): XQ001 uploader rate, XQ002 uploader byte quota,
-- XQ005 network rate, XQ006 network byte quota (the editor-cache codes), XQ007 the facts are maintainer-rejected,
-- 22023 malformed argument.
--
-- Accepted residuals (the client spot check is the real defence; tiers only order):
--   * After the 180-day unlink a contribution no longer names its uploader, so the same user can confirm the same
--     facts again and count twice (verified then needs only one more independent network).
--   * Quarantine is not a ban: it can be escaped by reaching `verified`, by withdraw + re-share (a new row once the
--     old one is orphaned) or by changing any fact (a new fact hash). Only `rejected` (maintainer) is sticky.
--   * Withdraw + re-share churn is not caught by the uploader limits (they count the uploader's current
--     contributions); the network limits are, because their counters outlive the withdrawal.

-- ───────────────────────────── sources (public) ─────────────────────────────

create table if not exists public.definition_sources (
  id                 uuid        primary key default gen_random_uuid(),
  model              smallint    not null check (model in (16, 17, 18)),          -- Axe-Fx III, FM3, FM9
  -- Device firmware in canonical form (no leading zeros: '13.0', never '13.00' / '013.0'), the lookup key.
  firmware           text        not null check (firmware ~ '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$'),
  kind               text        not null check (kind in ('editor-cache', 'live-full', 'live-readonly')),
  raw_format         smallint    not null check (raw_format between 1 and 100),
  fact_hash          text        not null check (fact_hash ~ '^[0-9a-f]{64}$'),  -- server-computed
  source             jsonb       not null,                                        -- sanitized raw source (first uploader's)
  summary            jsonb       not null default '{}'::jsonb,                    -- server-computed counts (first uploader's)
  -- Best confirmed quality: for a live source a confirmation with a cleaner walk raises it (the fact hash excludes
  -- walk statistics, so the first uploader's lossy walk must not cap the row).
  quality            smallint    not null check (quality between 0 and 3),
  coverage_score     integer     not null default 0 check (coverage_score >= 0),
  bytes              integer     not null check (bytes > 0 and bytes <= 2097152), -- canonical JSON length
  tier               text        not null default 'candidate'
                                 check (tier in ('candidate', 'verified', 'official', 'rejected')),
  -- The maintainer set the tier: sticky (never recomputed) and kept without contributions.
  pinned             boolean     not null default false,
  contributors       integer     not null default 0 check (contributors >= 0),   -- contribution rows
  networks           integer     not null default 0 check (networks >= 0),       -- of them, first of their network
  spot_passes        integer     not null default 0 check (spot_passes >= 0),    -- distinct reporting networks,
  spot_failures      integer     not null default 0 check (spot_failures >= 0),  -- high-water marks
  -- Derived, so it can never disagree with the tier, the pin or the counters (thresholds: README / M4 contract).
  quarantined        boolean     generated always as (
                       tier = 'candidate' and not pinned and spot_failures >= 3 and spot_failures > spot_passes) stored,
  -- Precise times: server-side only (ranking tie-break), NOT in the client column grant.
  first_seen         timestamptz not null default now(),
  last_confirmed_at  timestamptz,                                                 -- latest confirming contribution
  -- What clients see instead: the UTC day (a precise time could be matched against an uploader's activity).
  first_seen_day     date        generated always as ((first_seen at time zone 'UTC')::date) stored,
  last_confirmed_day date        generated always as ((last_confirmed_at at time zone 'UTC')::date) stored,
  constraint definition_sources_fact_key unique (model, firmware, kind, fact_hash),
  -- Target of the contributions' composite foreign key: a vote always names its source's (model, firmware, kind).
  constraint definition_sources_key_ref unique (id, model, firmware, kind),
  constraint definition_sources_size_guard check (octet_length(source::text) <= 4194304),
  constraint definition_sources_summary_guard
    check (jsonb_typeof(summary) = 'object' and octet_length(summary::text) <= 2048),
  -- official / rejected only as maintainer pins (an unpinned one would be recomputed away by the next vote).
  constraint definition_sources_pinned_tier check (pinned or tier in ('candidate', 'verified')),
  -- Backstop for the edge function's sanitizer (privacy, M4 contract §3.1): a stored source is an object of this
  -- row's kind and firmware without receiver-assigned or identifying fields: no `id` / `origin`, no tolerant-parse
  -- `issues`, no file hash (`contentSha256` absent or JSON null), `capturedAt` only as a UTC day (or absent/null),
  -- no free-text `walk.abortReason`. (coalesce: a CHECK passes on NULL, so a missing `kind` / `firmware` must fail
  -- explicitly.)
  constraint definition_sources_shared_shape check (
    jsonb_typeof(source) = 'object'
    and coalesce(source ->> 'kind' = kind, false)
    and coalesce(source ->> 'firmware' = firmware, false)
    and not (source ?| array['id', 'origin', 'issues'])
    and coalesce(source -> 'contentSha256', 'null'::jsonb) = 'null'::jsonb
    and (coalesce(source -> 'capturedAt', 'null'::jsonb) = 'null'::jsonb
         or (jsonb_typeof(source -> 'capturedAt') = 'string'
             and source ->> 'capturedAt' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00\.000Z$'))
    and coalesce(not ((source -> 'walk') ? 'abortReason'), true))
);

create index if not exists definition_sources_lookup_idx
  on public.definition_sources (model, firmware, kind) where tier <> 'rejected' and not quarantined;

alter table public.definition_sources enable row level security;

-- Servable rows only: not rejected, not quarantined, and not an orphan waiting for the cleanup (a source whose last
-- contribution went with an account deletion is hidden at once, not only after the next gc-blobs run).
drop policy if exists "definition sources are public" on public.definition_sources;
create policy "definition sources are public" on public.definition_sources
  for select to anon, authenticated
  using (tier <> 'rejected' and not quarantined and (pinned or contributors > 0));

-- Column-level on purpose (as device_profiles in 20261121150000_explicit_grants.sql): a column added later is not
-- readable by clients until it is granted, and the precise first_seen / last_confirmed_at stay server-side. Order
-- matters: revoking at table level also drops column grants.
revoke all on public.definition_sources from anon, authenticated;
grant select (id, model, firmware, kind, raw_format, fact_hash, source, summary, quality, coverage_score, bytes,
              tier, pinned, contributors, networks, spot_passes, spot_failures, quarantined, first_seen_day,
              last_confirmed_day)
  on public.definition_sources to anon, authenticated;
-- Edge function (GET /source/<id>, listings) and the maintainer (pin official/rejected, delete).
grant select, insert, update, delete on public.definition_sources to service_role;

-- ───────────────────────────── contributions (private) ─────────────────────────────

create table if not exists public.definition_source_contributions (
  id               uuid        primary key default gen_random_uuid(),
  source_id        uuid        not null,
  user_id          uuid        references auth.users(id) on delete cascade,   -- null once unlinked
  network_key      text        check (network_key ~ '^[0-9a-f]{64}$'),        -- HMAC of the network; null once unlinked
  -- No other linked contribution of the same source had this network key when this one was made.
  first_of_network boolean     not null,
  model            smallint    not null,                                       -- = the source's (composite FK)
  firmware         text        not null,
  kind             text        not null,
  app              jsonb       not null default '{}'::jsonb,                    -- version stamps only; cleared on unlink
  consent_at       timestamptz not null,                                       -- coarsened to the day on unlink
  consent_version  smallint    not null check (consent_version >= 1),
  created_at       timestamptz not null default now(),
  linked_until     timestamptz not null default now() + interval '180 days',
  constraint definition_source_contributions_once unique (source_id, user_id),
  constraint definition_source_contributions_source_fk foreign key (source_id, model, firmware, kind)
    references public.definition_sources (id, model, firmware, kind) on delete cascade,
  -- Linked (both set) or unlinked (both null); never half.
  constraint definition_source_contributions_link check ((user_id is null) = (network_key is null)),
  constraint definition_source_contributions_app_guard
    check (jsonb_typeof(app) = 'object' and octet_length(app::text) <= 1024)
);

-- One vote per uploader and (model, firmware, kind): a new share of the same kind replaces the old one.
create unique index if not exists definition_source_contributions_one_per_kind
  on public.definition_source_contributions (user_id, model, firmware, kind) where user_id is not null;
create index if not exists definition_source_contributions_user_idx
  on public.definition_source_contributions (user_id, created_at desc);       -- uploader limits, /mine, deletion
create index if not exists definition_source_contributions_link_idx
  on public.definition_source_contributions (linked_until) where user_id is not null;  -- unlink sweep
-- (Lookups by source use the leading source_id of definition_source_contributions_once; the network limits read
-- definition_source_network_usage, so no network-key index is needed here.)

alter table public.definition_source_contributions enable row level security;
-- No policies on purpose: uploaders see their own rows only through the edge function (GET /mine).
revoke all on public.definition_source_contributions from anon, authenticated;
grant select, insert, update, delete on public.definition_source_contributions to service_role;

-- ───────────────────────────── reports (private) ─────────────────────────────
-- Spot-check outcomes. `answered` = targets the device answered (match or mismatch), so
-- mismatches <= answered <= checked, and a verdict is `failed` exactly when a mismatch was found.

create table if not exists public.definition_source_reports (
  id          uuid        primary key default gen_random_uuid(),
  source_id   uuid        not null references public.definition_sources(id) on delete cascade,
  user_id     uuid        not null references auth.users(id) on delete cascade,
  network_key text        not null check (network_key ~ '^[0-9a-f]{64}$'),
  verdict     text        not null check (verdict in ('passed', 'failed')),
  checked     smallint    not null check (checked between 0 and 64),
  answered    smallint    not null check (answered between 0 and 64),
  mismatches  smallint    not null check (mismatches between 0 and 64),
  app         jsonb       not null default '{}'::jsonb,
  created_at  timestamptz not null default now(),
  constraint definition_source_reports_once unique (source_id, user_id),
  constraint definition_source_reports_counts check (answered <= checked and mismatches <= answered),
  constraint definition_source_reports_verdict check ((verdict = 'failed') = (mismatches > 0)),
  constraint definition_source_reports_app_guard
    check (jsonb_typeof(app) = 'object' and octet_length(app::text) <= 1024)
);

create index if not exists definition_source_reports_created_idx
  on public.definition_source_reports (created_at);                           -- 180-day retention
create index if not exists definition_source_reports_user_idx
  on public.definition_source_reports (user_id, created_at desc);             -- uploader limit, deletion

alter table public.definition_source_reports enable row level security;
revoke all on public.definition_source_reports from anon, authenticated;
grant select, insert, update, delete on public.definition_source_reports to service_role;

-- ───────────────────────────── network usage counters (private) ─────────────────────────────
-- One row per accepted contribution or report: the keyed network hash (never the address), what it was and the
-- canonical bytes of a contribution. No user id. Deleted after 30 days (the longest limit window) by
-- unlink_expired_definition_contributions().

create table if not exists public.definition_source_network_usage (
  id          bigint      generated always as identity primary key,
  network_key text        not null check (network_key ~ '^[0-9a-f]{64}$'),
  action      text        not null check (action in ('contribute', 'report')),
  bytes       integer     not null default 0 check (bytes >= 0),
  created_at  timestamptz not null default now()
);

create index if not exists definition_source_network_usage_key_idx
  on public.definition_source_network_usage (network_key, action, created_at desc);
create index if not exists definition_source_network_usage_created_idx
  on public.definition_source_network_usage (created_at);

alter table public.definition_source_network_usage enable row level security;
revoke all on public.definition_source_network_usage from anon, authenticated;
-- The maintainer may inspect and prune them; they are written only by the functions below.
grant select, delete on public.definition_source_network_usage to service_role;

-- ───────────────────────────── internal: counters + tier ─────────────────────────────
-- contributors = contribution rows (linked or unlinked), networks = those that were first of their network. Both
-- survive unlinking (the rows stay) and drop on withdrawal/account deletion (the rows go). The tier is recomputed
-- unless pinned. THE verify rule (the only place it lives, so it cannot differ between paths): quality 3 and at
-- least 2 contributors on at least 2 networks. Callers hold the source-key lock and run as the owner (the definer
-- functions and the trigger below), so this needs no SECURITY DEFINER of its own; executable by nobody else.
create or replace function public.definition_source_refresh(p_source_id uuid)
returns void
language plpgsql
set search_path = public
as $$
begin
  update public.definition_sources s
     set contributors = c.n,
         networks     = c.nets,
         tier         = case
                          when s.pinned then s.tier
                          when s.quality = 3 and c.n >= 2 and c.nets >= 2 then 'verified'
                          else 'candidate'
                        end
    from (select count(*)::integer as n,
                 (count(*) filter (where x.first_of_network))::integer as nets
            from public.definition_source_contributions x
           where x.source_id = p_source_id) c
   where s.id = p_source_id;
end;
$$;

revoke execute on function public.definition_source_refresh(uuid) from public, anon, authenticated, service_role;

-- Every removal of a contribution — withdrawal, a replaced vote, the auth.users cascade of an account deletion, a
-- maintainer or service-role delete — recomputes its source's counters and tier, so no path leaves them stale.
-- (Orphans are not deleted here: withdraw does that itself, account deletion calls withdraw first and the cleanup
-- catches the rest; until then the RLS policy and the selection hide them.)
-- SECURITY DEFINER because the cascade from auth.users runs as another role; EXECUTE is checked when the trigger
-- is created, not when it fires, so nobody needs a grant.
create or replace function public.definition_source_contribution_removed()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform pg_advisory_xact_lock(hashtext('defsrc:key'),
                                hashtext(old.model::text || '/' || old.firmware || '/' || old.kind));
  perform public.definition_source_refresh(old.source_id);
  return null;
end;
$$;

revoke execute on function public.definition_source_contribution_removed()
  from public, anon, authenticated, service_role;

drop trigger if exists definition_source_contributions_removed on public.definition_source_contributions;
create trigger definition_source_contributions_removed
  after delete on public.definition_source_contributions
  for each row execute function public.definition_source_contribution_removed();

-- ───────────────────────────── contribute ─────────────────────────────
-- Atomic share of one sanitized source (the edge function computed fact hash, summary, quality, coverage score and
-- canonical bytes). In order, under the uploader, network and source-key locks:
--   0. the facts are already in and the maintainer rejected them -> XQ007, nothing changes (no vote is moved, no
--      limit charged);
--   1. this uploader already has a linked contribution to the source with these facts -> deduped, nothing changes
--      and no limit is charged (a client retry);
--   2. limits: uploader rate XQ001 and byte quota XQ002 (over the uploader's contributions), network rate XQ005
--      and byte quota XQ006 (over the network usage counters, which outlive withdrawals);
--   3. one vote per uploader and kind: the uploader's linked contribution to ANOTHER source of the same (model,
--      firmware, kind) is deleted (the trigger recomputes that source) and the source is deleted if orphaned and
--      not pinned;
--   4. the source row: inserted (created) or, when the facts are already in, confirmed — the stored content and
--      summary stay the first uploader's; a live confirmation raises `quality` to the better walk's;
--   5. the contribution row (first_of_network = no other linked contribution of the source has this network key)
--      and a network usage counter;
--   6. counters + tier recomputed (unless pinned); a confirmation sets last_confirmed_at.
-- Returns created / deduped / confirmed (this call added a contributor), the tier and the counters after the call.
create or replace function public.contribute_definition_source(
  p_user_id               uuid,
  p_network_key           text,
  p_model                 integer,
  p_firmware              text,
  p_kind                  text,
  p_raw_format            integer,
  p_fact_hash             text,
  p_source                jsonb,
  p_summary               jsonb,
  p_quality               integer,
  p_coverage_score        integer,
  p_bytes                 integer,
  p_app                   jsonb,
  p_consent_at            timestamptz,
  p_consent_version       integer,
  p_max_per_window        integer default 10,
  p_window_seconds        integer default 3600,
  p_net_max_per_window    integer default 10,
  p_quota_bytes           bigint  default 41943040,   -- 40 MiB
  p_quota_window_seconds  integer default 2592000,    -- 30 days
  p_net_quota_bytes       bigint  default 41943040    -- 40 MiB
) returns table (source_id uuid, created boolean, deduped boolean, confirmed boolean, tier text,
                 contributors integer, networks integer)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_src     public.definition_sources%rowtype;
  v_id      uuid;
  v_created boolean := false;
  v_old     uuid;
  v_first   boolean;
  v_n       integer;
  v_oldest  timestamptz;
  v_used    bigint;
  v_need    bigint;
  v_freed   bigint;
  v_retry   integer;
  v_rec     record;
begin
  if p_user_id is null then
    raise exception 'definition_source_invalid_user' using errcode = '22023';
  end if;
  if p_network_key is null or p_network_key !~ '^[0-9a-f]{64}$' then
    raise exception 'definition_source_invalid_network_key' using errcode = '22023';
  end if;
  if p_kind is null or p_kind not in ('editor-cache', 'live-full', 'live-readonly') then
    raise exception 'definition_source_invalid_kind' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtext('defsrc:user'), hashtext(p_user_id::text));
  perform pg_advisory_xact_lock(hashtext('defsrc:net'), hashtext(p_network_key));
  perform pg_advisory_xact_lock(hashtext('defsrc:key'), hashtext(p_model::text || '/' || p_firmware || '/' || p_kind));

  select * into v_src
    from public.definition_sources s
   where s.model = p_model and s.firmware = p_firmware and s.kind = p_kind and s.fact_hash = p_fact_hash;

  -- 0. Maintainer-rejected facts: refused before anything moves.
  if v_src.id is not null and v_src.tier = 'rejected' then
    raise exception 'definition_source_rejected' using errcode = 'XQ007';
  end if;

  -- 1. Own dedupe.
  if v_src.id is not null and exists (
    select 1 from public.definition_source_contributions c
     where c.source_id = v_src.id and c.user_id = p_user_id
  ) then
    return query select v_src.id, false, true, false, v_src.tier, v_src.contributors, v_src.networks;
    return;
  end if;

  -- 2a. Uploader rate limit over the newest p_max_per_window contributions inside the window.
  select count(*), min(t.created_at) into v_n, v_oldest
    from (
      select c.created_at
        from public.definition_source_contributions c
       where c.user_id = p_user_id
         and c.created_at > now() - make_interval(secs => p_window_seconds)
       order by c.created_at desc
       limit p_max_per_window
    ) t;
  if v_n >= p_max_per_window then
    v_retry := greatest(1, ceil(extract(epoch from (v_oldest + make_interval(secs => p_window_seconds) - now())))::integer);
    raise exception 'definition_source_rate_limited' using errcode = 'XQ001', detail = v_retry::text;
  end if;

  -- 2b. Network rate limit.
  select count(*), min(t.created_at) into v_n, v_oldest
    from (
      select u.created_at
        from public.definition_source_network_usage u
       where u.network_key = p_network_key and u.action = 'contribute'
         and u.created_at > now() - make_interval(secs => p_window_seconds)
       order by u.created_at desc
       limit p_net_max_per_window
    ) t;
  if v_n >= p_net_max_per_window then
    v_retry := greatest(1, ceil(extract(epoch from (v_oldest + make_interval(secs => p_window_seconds) - now())))::integer);
    raise exception 'definition_source_network_rate_limited' using errcode = 'XQ005', detail = v_retry::text;
  end if;

  -- 2c. Uploader byte quota: the canonical bytes of every source the uploader contributed to inside the window.
  --     Retry hint: when enough of the oldest contributions have left the window.
  select coalesce(sum(s.bytes), 0) into v_used
    from public.definition_source_contributions c
    join public.definition_sources s on s.id = c.source_id
   where c.user_id = p_user_id
     and c.created_at > now() - make_interval(secs => p_quota_window_seconds);
  if v_used + p_bytes > p_quota_bytes then
    v_need  := v_used + p_bytes - p_quota_bytes;
    v_retry := p_quota_window_seconds;
    v_freed := 0;
    for v_rec in
      select s.bytes as charge, c.created_at + make_interval(secs => p_quota_window_seconds) as frees_at
        from public.definition_source_contributions c
        join public.definition_sources s on s.id = c.source_id
       where c.user_id = p_user_id
         and c.created_at > now() - make_interval(secs => p_quota_window_seconds)
       order by c.created_at asc
    loop
      v_freed := v_freed + v_rec.charge;
      if v_freed >= v_need then
        v_retry := greatest(1, ceil(extract(epoch from (v_rec.frees_at - now())))::integer);
        exit;
      end if;
    end loop;
    raise exception 'definition_source_quota_exceeded' using errcode = 'XQ002', detail = v_retry::text;
  end if;

  -- 2d. Network byte quota.
  select coalesce(sum(u.bytes), 0) into v_used
    from public.definition_source_network_usage u
   where u.network_key = p_network_key and u.action = 'contribute'
     and u.created_at > now() - make_interval(secs => p_quota_window_seconds);
  if v_used + p_bytes > p_net_quota_bytes then
    v_need  := v_used + p_bytes - p_net_quota_bytes;
    v_retry := p_quota_window_seconds;
    v_freed := 0;
    for v_rec in
      select u.bytes as charge, u.created_at + make_interval(secs => p_quota_window_seconds) as frees_at
        from public.definition_source_network_usage u
       where u.network_key = p_network_key and u.action = 'contribute'
         and u.created_at > now() - make_interval(secs => p_quota_window_seconds)
       order by u.created_at asc
    loop
      v_freed := v_freed + v_rec.charge;
      if v_freed >= v_need then
        v_retry := greatest(1, ceil(extract(epoch from (v_rec.frees_at - now())))::integer);
        exit;
      end if;
    end loop;
    raise exception 'definition_source_network_quota_exceeded' using errcode = 'XQ006', detail = v_retry::text;
  end if;

  -- 3. One vote per uploader and kind: move the vote (the delete trigger recomputes the old source).
  delete from public.definition_source_contributions c
   where c.user_id = p_user_id and c.model = p_model and c.firmware = p_firmware and c.kind = p_kind
     and c.source_id is distinct from v_src.id
  returning c.source_id into v_old;
  if v_old is not null then
    delete from public.definition_sources s
     where s.id = v_old and not s.pinned
       and not exists (select 1 from public.definition_source_contributions c where c.source_id = s.id);
  end if;

  -- 4. The source row.
  if v_src.id is null then
    insert into public.definition_sources
      (model, firmware, kind, raw_format, fact_hash, source, summary, quality, coverage_score, bytes)
    values
      (p_model, p_firmware, p_kind, p_raw_format, p_fact_hash, p_source, coalesce(p_summary, '{}'::jsonb),
       p_quality, coalesce(p_coverage_score, 0), p_bytes)
    on conflict on constraint definition_sources_fact_key do nothing
    returning id into v_id;
    if v_id is null then
      select s.id into v_id
        from public.definition_sources s
       where s.model = p_model and s.firmware = p_firmware and s.kind = p_kind and s.fact_hash = p_fact_hash;
    else
      v_created := true;
    end if;
  else
    v_id := v_src.id;
  end if;

  -- 5. The contribution and its network usage counter.
  v_first := not exists (
    select 1 from public.definition_source_contributions c
     where c.source_id = v_id and c.network_key = p_network_key
  );
  insert into public.definition_source_contributions
    (source_id, user_id, network_key, first_of_network, model, firmware, kind, app, consent_at, consent_version)
  values
    (v_id, p_user_id, p_network_key, v_first, p_model, p_firmware, p_kind, coalesce(p_app, '{}'::jsonb),
     p_consent_at, p_consent_version);
  insert into public.definition_source_network_usage (network_key, action, bytes)
  values (p_network_key, 'contribute', p_bytes);

  -- 6. Counters and tier (a confirmation first records itself and, for a live source, its walk quality).
  if not v_created then
    update public.definition_sources s
       set last_confirmed_at = now(),
           quality = case when s.kind = 'editor-cache' then s.quality else greatest(s.quality, p_quality) end
     where s.id = v_id;
  end if;
  perform public.definition_source_refresh(v_id);

  select * into v_src from public.definition_sources s where s.id = v_id;
  return query select v_id, v_created, not v_created, not v_created, v_src.tier, v_src.contributors, v_src.networks;
end;
$$;

revoke execute on function public.contribute_definition_source(uuid, text, integer, text, text, integer, text, jsonb, jsonb, integer, integer, integer, jsonb, timestamptz, integer, integer, integer, integer, bigint, integer, bigint)
  from public, anon, authenticated;
grant execute on function public.contribute_definition_source(uuid, text, integer, text, text, integer, text, jsonb, jsonb, integer, integer, integer, jsonb, timestamptz, integer, integer, integer, integer, bigint, integer, bigint)
  to service_role;

-- ───────────────────────────── withdraw ─────────────────────────────
-- The uploader withdraws one contribution (p_source_id) or all of them (optionally for one model / firmware). Only
-- LINKED contributions of p_user_id are touched; after unlinking (180 days) a contribution can no longer be
-- withdrawn. The trigger recomputes counters and tier; a source left without contributions is deleted unless
-- pinned. withdrawn = 0 means nothing of the caller's matched (the edge function answers 404 for a source id).
-- delete-account calls this (all) before deleting the auth user (see the header: sorted locks, orphans at once).
create or replace function public.withdraw_definition_contributions(
  p_user_id   uuid,
  p_source_id uuid    default null,
  p_model     integer default null,
  p_firmware  text    default null
) returns table (withdrawn integer, deleted_sources integer)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_rec       record;
  v_sources   uuid[];
  v_withdrawn integer;
  v_deleted   integer;
begin
  if p_user_id is null then
    raise exception 'definition_source_invalid_user' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtext('defsrc:user'), hashtext(p_user_id::text));
  for v_rec in
    select distinct c.model, c.firmware, c.kind
      from public.definition_source_contributions c
     where c.user_id = p_user_id
       and (p_source_id is null or c.source_id = p_source_id)
       and (p_model is null or c.model = p_model)
       and (p_firmware is null or c.firmware = p_firmware)
     order by 1, 2, 3
  loop
    perform pg_advisory_xact_lock(hashtext('defsrc:key'),
                                  hashtext(v_rec.model::text || '/' || v_rec.firmware || '/' || v_rec.kind));
  end loop;

  with gone as (
    delete from public.definition_source_contributions c
     where c.user_id = p_user_id
       and (p_source_id is null or c.source_id = p_source_id)
       and (p_model is null or c.model = p_model)
       and (p_firmware is null or c.firmware = p_firmware)
    returning c.source_id
  )
  select coalesce(array_agg(distinct g.source_id), '{}'::uuid[]), count(*)::integer
    into v_sources, v_withdrawn
    from gone g;

  delete from public.definition_sources s
   where s.id = any(v_sources) and not s.pinned
     and not exists (select 1 from public.definition_source_contributions c where c.source_id = s.id);
  get diagnostics v_deleted = row_count;

  return query select v_withdrawn, v_deleted;
end;
$$;

revoke execute on function public.withdraw_definition_contributions(uuid, uuid, integer, text)
  from public, anon, authenticated;
grant execute on function public.withdraw_definition_contributions(uuid, uuid, integer, text)
  to service_role;

-- ───────────────────────────── report ─────────────────────────────
-- A spot-check outcome from a client that already has a session. One report per (source, uploader): a repeat
-- replaces it (the latest verdict and network count). Limits: uploader XQ001 (reports inside the window), network
-- XQ005 (usage counters). spot_passes / spot_failures = distinct reporting networks per verdict, kept as high-water
-- marks (a report deleted later — retention, account deletion — does not lower them); `quarantined` follows from
-- the generated column. A report whose uploader OR network has a linked contribution to the source is STORED (the
-- maintainer sees it) but NOT COUNTED: contributors cannot vouch for, or grief, their own row. Returns no row when
-- the source does not exist (the edge function answers 404).
create or replace function public.report_definition_source(
  p_user_id            uuid,
  p_network_key        text,
  p_source_id          uuid,
  p_verdict            text,
  p_checked            integer,
  p_answered           integer,
  p_mismatches         integer,
  p_app                jsonb,
  p_max_per_window     integer default 30,
  p_net_max_per_window integer default 30,
  p_window_seconds     integer default 3600
) returns table (quarantined boolean)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_n      integer;
  v_oldest timestamptz;
  v_retry  integer;
  v_q      boolean;
begin
  if p_user_id is null then
    raise exception 'definition_source_invalid_user' using errcode = '22023';
  end if;
  if p_network_key is null or p_network_key !~ '^[0-9a-f]{64}$' then
    raise exception 'definition_source_invalid_network_key' using errcode = '22023';
  end if;
  if p_verdict is null or p_verdict not in ('passed', 'failed') then
    raise exception 'definition_source_invalid_verdict' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtext('defsrc:user'), hashtext(p_user_id::text));
  perform pg_advisory_xact_lock(hashtext('defsrc:net'), hashtext(p_network_key));

  -- Serializes reports on one source, so each recount below sees every committed report before it.
  perform 1 from public.definition_sources s where s.id = p_source_id for no key update;
  if not found then
    return;
  end if;

  select count(*), min(t.created_at) into v_n, v_oldest
    from (
      select r.created_at
        from public.definition_source_reports r
       where r.user_id = p_user_id
         and r.created_at > now() - make_interval(secs => p_window_seconds)
       order by r.created_at desc
       limit p_max_per_window
    ) t;
  if v_n >= p_max_per_window then
    v_retry := greatest(1, ceil(extract(epoch from (v_oldest + make_interval(secs => p_window_seconds) - now())))::integer);
    raise exception 'definition_report_rate_limited' using errcode = 'XQ001', detail = v_retry::text;
  end if;

  select count(*), min(t.created_at) into v_n, v_oldest
    from (
      select u.created_at
        from public.definition_source_network_usage u
       where u.network_key = p_network_key and u.action = 'report'
         and u.created_at > now() - make_interval(secs => p_window_seconds)
       order by u.created_at desc
       limit p_net_max_per_window
    ) t;
  if v_n >= p_net_max_per_window then
    v_retry := greatest(1, ceil(extract(epoch from (v_oldest + make_interval(secs => p_window_seconds) - now())))::integer);
    raise exception 'definition_report_network_rate_limited' using errcode = 'XQ005', detail = v_retry::text;
  end if;

  insert into public.definition_source_reports
    (source_id, user_id, network_key, verdict, checked, answered, mismatches, app)
  values
    (p_source_id, p_user_id, p_network_key, p_verdict, p_checked, p_answered, p_mismatches,
     coalesce(p_app, '{}'::jsonb))
  on conflict on constraint definition_source_reports_once do update set
    network_key = excluded.network_key,
    verdict     = excluded.verdict,
    checked     = excluded.checked,
    answered    = excluded.answered,
    mismatches  = excluded.mismatches,
    app         = excluded.app,
    created_at  = now();
  insert into public.definition_source_network_usage (network_key, action, bytes)
  values (p_network_key, 'report', 0);

  update public.definition_sources s
     set spot_passes   = greatest(s.spot_passes, (
                           select count(distinct r.network_key)::integer from public.definition_source_reports r
                            where r.source_id = s.id and r.verdict = 'passed'
                              and not exists (select 1 from public.definition_source_contributions c
                                               where c.source_id = r.source_id
                                                 and (c.user_id = r.user_id or c.network_key = r.network_key)))),
         spot_failures = greatest(s.spot_failures, (
                           select count(distinct r.network_key)::integer from public.definition_source_reports r
                            where r.source_id = s.id and r.verdict = 'failed'
                              and not exists (select 1 from public.definition_source_contributions c
                                               where c.source_id = r.source_id
                                                 and (c.user_id = r.user_id or c.network_key = r.network_key))))
   where s.id = p_source_id
  returning s.quarantined into v_q;

  return query select v_q;
end;
$$;

revoke execute on function public.report_definition_source(uuid, text, uuid, text, integer, integer, integer, jsonb, integer, integer, integer)
  from public, anon, authenticated;
grant execute on function public.report_definition_source(uuid, text, uuid, text, integer, integer, integer, jsonb, integer, integer, integer)
  to service_role;

-- ───────────────────────────── selection (ranking) ─────────────────────────────
-- The best servable row per kind for (model, firmware) and raw formats the caller can read, without the source
-- body (fetched per id) and with day-granular dates only. `alternatives` = servable rows of that kind (the best one
-- included). Kinds are never compared with each other; inside a kind the order is tier -> quality -> coverage score
-- -> contributors -> networks -> oldest (precise first_seen, server-side only) -> id, so a newer row never wins on
-- its date. Invoker rights: its only caller is the service role (table SELECT, bypasses RLS), so it filters the
-- servable rows itself — the same condition as the public policy.
create or replace function public.select_definition_sources(
  p_model          integer,
  p_firmware       text,
  p_raw_format_max integer
) returns table (id uuid, kind text, raw_format smallint, fact_hash text, tier text, quality smallint,
                 coverage_score integer, contributors integer, networks integer, spot_passes integer,
                 spot_failures integer, first_seen_day date, last_confirmed_day date, bytes integer,
                 summary jsonb, alternatives integer)
language sql
stable
set search_path = public
as $$
  select r.id, r.kind, r.raw_format, r.fact_hash, r.tier, r.quality, r.coverage_score, r.contributors, r.networks,
         r.spot_passes, r.spot_failures, r.first_seen_day, r.last_confirmed_day, r.bytes, r.summary, r.alternatives
    from (
      select s.id, s.kind, s.raw_format, s.fact_hash, s.tier, s.quality, s.coverage_score, s.contributors,
             s.networks, s.spot_passes, s.spot_failures, s.first_seen_day, s.last_confirmed_day, s.bytes, s.summary,
             (count(*) over (partition by s.kind))::integer as alternatives,
             row_number() over (
               partition by s.kind
               order by case s.tier when 'official' then 0 when 'verified' then 1 else 2 end,
                        s.quality desc, s.coverage_score desc, s.contributors desc, s.networks desc,
                        s.first_seen asc, s.id asc) as pos
        from public.definition_sources s
       where s.model = p_model and s.firmware = p_firmware and s.raw_format <= p_raw_format_max
         and s.tier <> 'rejected' and not s.quarantined and (s.pinned or s.contributors > 0)
    ) r
   where r.pos = 1
   order by case r.kind when 'editor-cache' then 0 when 'live-full' then 1 else 2 end;
$$;

revoke execute on function public.select_definition_sources(integer, text, integer)
  from public, anon, authenticated;
grant execute on function public.select_definition_sources(integer, text, integer)
  to service_role;

-- ───────────────────────────── orphan cleanup ─────────────────────────────
-- Deletes sources without any contribution that are not pinned (called by delete-account after withdrawing a
-- user's contributions, and by gc-blobs). Each candidate is re-checked under its source-key lock, so a contribution
-- made meanwhile keeps it. Returns the number of deleted sources.
create or replace function public.cleanup_orphan_definition_sources()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_rec   record;
  v_n     integer;
  v_total integer := 0;
begin
  for v_rec in
    select s.id, s.model, s.firmware, s.kind
      from public.definition_sources s
     where not s.pinned
       and not exists (select 1 from public.definition_source_contributions c where c.source_id = s.id)
     order by s.model, s.firmware, s.kind, s.id
  loop
    perform pg_advisory_xact_lock(hashtext('defsrc:key'),
                                  hashtext(v_rec.model::text || '/' || v_rec.firmware || '/' || v_rec.kind));
    delete from public.definition_sources s
     where s.id = v_rec.id and not s.pinned
       and not exists (select 1 from public.definition_source_contributions c where c.source_id = s.id);
    get diagnostics v_n = row_count;
    v_total := v_total + v_n;
  end loop;
  return v_total;
end;
$$;

revoke execute on function public.cleanup_orphan_definition_sources() from public, anon, authenticated;
grant execute on function public.cleanup_orphan_definition_sources() to service_role;

-- ───────────────────────────── retention ─────────────────────────────
-- Called daily by gc-blobs:
--   * contributions whose link expired (linked_until, 180 days) are UNLINKED: user id and network key nulled, app
--     stamps cleared, consent time coarsened to the UTC day. The row stays, so the source's counters and tier stay
--     and the content stays published; the uploader can no longer withdraw it individually (stated in the share
--     consent text).
--   * reports older than p_report_retention (180 days) are deleted; the counters on the source are high-water
--     marks and stay.
--   * network usage counters older than p_usage_retention (30 days, the longest limit window) are deleted.
-- p_now makes the sweep testable with shifted time.
create or replace function public.unlink_expired_definition_contributions(
  p_now              timestamptz default now(),
  p_report_retention interval    default interval '180 days',
  p_usage_retention  interval    default interval '30 days'
) returns table (unlinked integer, reports_deleted integer, usage_deleted integer)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
declare
  v_unlinked integer;
  v_reports  integer;
  v_usage    integer;
begin
  update public.definition_source_contributions c
     set user_id     = null,
         network_key = null,
         app         = '{}'::jsonb,
         consent_at  = date_trunc('day', c.consent_at, 'UTC')
   where c.user_id is not null and c.linked_until < p_now;
  get diagnostics v_unlinked = row_count;

  delete from public.definition_source_reports r where r.created_at < p_now - p_report_retention;
  get diagnostics v_reports = row_count;

  delete from public.definition_source_network_usage u where u.created_at < p_now - p_usage_retention;
  get diagnostics v_usage = row_count;

  return query select v_unlinked, v_reports, v_usage;
end;
$$;

revoke execute on function public.unlink_expired_definition_contributions(timestamptz, interval, interval)
  from public, anon, authenticated;
grant execute on function public.unlink_expired_definition_contributions(timestamptz, interval, interval)
  to service_role;
