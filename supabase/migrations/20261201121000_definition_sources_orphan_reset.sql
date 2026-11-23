-- Shared device definitions: an identical share of an ORPHANED source starts a fresh row instead of reviving the
-- old one (follow-up to 20261201120000_definition_sources.sql, which stays as applied).
--
-- An orphan is an unpinned source without any contribution: its last vote went with a withdrawal (withdraw deletes
-- the orphan at once) or with an account deletion through the auth.users cascade (the orphan waits, hidden, for
-- cleanup_orphan_definition_sources()). Until that cleanup ran, contribute_definition_source() found the old row by
-- its fact hash and "confirmed" it: the caller got created = false / confirmed = true although nobody else held the
-- facts, the row kept its old `first_seen` (which wins ranking ties: oldest first) and the previous uploader's
-- stored body, summary and spot-check counters. Now, under the same source-key lock, such a row is deleted (its
-- reports go with it by cascade) and the share inserts a new one, exactly as if the cleanup had run first.
-- Pinned rows (`official`, `rejected`) are never reset: they are kept without contributions on purpose.
--
-- The reset happens inside the function, before the limits: when a limit refuses the share, the statement fails
-- and the deletion is rolled back with it (the orphan stays for the cleanup). Same signature, privileges and
-- answers as before otherwise; only step 0b is new.

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

  -- 0b. An orphan (unpinned, no contribution left) is not revived: delete it and share as new. The source-key lock
  --     held above is the one every contribution to this key takes, so no contribution can appear meanwhile.
  if v_src.id is not null and not v_src.pinned and not exists (
    select 1 from public.definition_source_contributions c where c.source_id = v_src.id
  ) then
    delete from public.definition_sources s where s.id = v_src.id;
    select * into v_src
      from public.definition_sources s
     where s.model = p_model and s.firmware = p_firmware and s.kind = p_kind and s.fact_hash = p_fact_hash;
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

-- Unchanged privileges, restated so this file stands on its own.
revoke execute on function public.contribute_definition_source(uuid, text, integer, text, text, integer, text, jsonb, jsonb, integer, integer, integer, jsonb, timestamptz, integer, integer, integer, integer, bigint, integer, bigint)
  from public, anon, authenticated;
grant execute on function public.contribute_definition_source(uuid, text, integer, text, text, integer, text, jsonb, jsonb, integer, integer, integer, jsonb, timestamptz, integer, integer, integer, integer, bigint, integer, bigint)
  to service_role;
