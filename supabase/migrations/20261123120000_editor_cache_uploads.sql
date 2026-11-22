-- Editor-cache uploads: a user (a signed-in account OR a Supabase anonymous session) may contribute the
-- definitions file the official Fractal editor saved for their device, so the maintainer can prepare
-- definition updates for a firmware Axis does not know yet. The client (ForgeFX) redacts the user's own
-- names (preset names, user cab names) BEFORE upload; the `editor-caches` edge function re-checks the stored
-- file (structure walk + redaction) before it accepts it.
--
-- Flow (signed upload, like diagnostic captures): reserve (this file's reserve function, via the edge
-- function) -> the client uploads straight to the private bucket -> finalize (size + server-side sha256 +
-- structure/redaction check, then this file's complete function). Nothing here is readable by clients.
--
-- Objects:
--   * editor_cache_uploads   one row per upload (no IP address, no e-mail, no path, no telemetry id; the
--                            uploader is the auth user id only — anonymous or account).
--   * editor_cache_coverage  per (model, firmware): 'collecting' | 'covered' | 'closed'. No user data. Drives
--                            the public "is this firmware wanted?" answer, which reveals nothing else.
--   * editor_cache_ip_usage  per-network counters: a KEYED HASH of the client's network (never the address
--                            itself), linked to the upload while it exists (rate limits + one-network-counts-
--                            once coverage), deleted 30 days after creation once unlinked.
--   * bucket editor-caches   private, 4 MiB, application/octet-stream, no storage policy.
--
-- Access model — deny by default, twice over (same as diagnostic_captures): RLS on with NO policy for any of
-- the three tables, and table privileges revoked from anon/authenticated. Rows are created only by the
-- SECURITY DEFINER functions below (EXECUTE for service_role only); the service role (edge functions,
-- maintainer) reads, finalizes and deletes.

-- ───────────────────────────── uploads ─────────────────────────────

create table if not exists public.editor_cache_uploads (
  id               uuid        primary key default gen_random_uuid(),
  user_id          uuid        not null references auth.users(id) on delete cascade,
  model            smallint    not null check (model between 0 and 255),            -- Fractal model byte
  device_firmware  text        not null check (device_firmware ~ '^\d{1,3}\.\d{1,3}$'),  -- as the device reports it
  file_version     text        check (file_version ~ '^\d{1,3}\.\d{1,3}$'),          -- from the file name
  -- The file's own version (its header). Set by finalize from the server-side check of the stored bytes, so it
  -- is verified, not a client claim (before finalize: the client's claim, if any).
  content_version  text        check (content_version ~ '^\d{1,3}\.\d{1,3}$'),
  -- Only uploads whose file (name or header) matches the device firmware count toward coverage.
  version_match    boolean     generated always as (
                     coalesce(file_version = device_firmware, false) or coalesce(content_version = device_firmware, false)) stored,
  file_name        text        not null check (file_name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$'),
  sha256           text        not null check (sha256 ~ '^[0-9a-f]{64}$'),   -- of the stored (redacted) bytes; verified at finalize
  bytes            integer     not null check (bytes > 0 and bytes <= 4194304), -- announced while pending, actual once complete
  redaction        jsonb       not null default '{}'::jsonb,   -- { version, tables, names } — counts only
  summary          jsonb       not null default '{}'::jsonb,   -- client validation numbers, known keys only (edge-sanitized)
  app              jsonb       not null default '{}'::jsonb,   -- { forgefx, codec, axis? } version stamps
  consent_at       timestamptz not null,                      -- when the user consented (client clock, edge-checked ±24 h)
  consent_version  smallint    not null check (consent_version >= 1),  -- which disclosure text was shown
  status           text        not null default 'pending' check (status in ('pending', 'complete')),
  object_path      text        not null,
  created_at       timestamptz not null default now(),
  expires_at       timestamptz not null default now() + interval '180 days',
  -- Idempotency: the same file from the same uploader is the same upload.
  unique (user_id, sha256),
  -- Everything (delete-account, retention GC, self-delete) relies on objects living under <user_id>/.
  constraint editor_cache_uploads_object_path_format check (object_path = user_id::text || '/' || sha256 || '.cache')
);

create index if not exists editor_cache_uploads_user_created_idx
  on public.editor_cache_uploads (user_id, created_at desc);                 -- rate limit, listing, account deletion
create index if not exists editor_cache_uploads_coverage_idx
  on public.editor_cache_uploads (model, device_firmware) where status = 'complete';  -- coverage count, cross-user dedup
create index if not exists editor_cache_uploads_expires_at_idx
  on public.editor_cache_uploads (expires_at);                                -- retention sweep
create index if not exists editor_cache_uploads_pending_idx
  on public.editor_cache_uploads (created_at) where status = 'pending';       -- stale-pending sweep

alter table public.editor_cache_uploads enable row level security;
-- No policies on purpose. Uploaders list and delete their own rows THROUGH the edge function (service role).
revoke all on public.editor_cache_uploads from anon, authenticated;

-- ───────────────────────────── coverage ─────────────────────────────

create table if not exists public.editor_cache_coverage (
  model            smallint    not null check (model between 0 and 255),
  device_firmware  text        not null check (device_firmware ~ '^\d{1,3}\.\d{1,3}$'),
  -- High-water mark of distinct uploaders with a complete, version-matched upload (never decremented by a
  -- withdrawal or expiry: there is no user data in it).
  contributors     integer     not null default 0 check (contributors >= 0),
  state            text        not null default 'collecting' check (state in ('collecting', 'covered', 'closed')),
  -- Set when the maintainer reopens a firmware: only uploads reserved after it count toward the next
  -- automatic 'covered', so the uploads that were judged insufficient cannot re-cover it on their own.
  reopened_at      timestamptz,
  updated_at       timestamptz not null default now(),
  primary key (model, device_firmware)
);

alter table public.editor_cache_coverage enable row level security;
revoke all on public.editor_cache_coverage from anon, authenticated;

-- ───────────────────────────── per-network rate-limit counters ─────────────────────────────
-- One row per NEW reservation. `ip_key` is an HMAC-SHA256 (hex) of the client's network (IPv4 address or IPv6
-- /64 prefix) under a server-side secret held only in the edge function's environment; the address itself is
-- never stored or logged. While the upload exists the row is linked to it (pending uploads are charged at the
-- upload cap, complete ones at their real size) and serves a second purpose: coverage counts uploaders at most
-- once per network key, so one network cannot cover a firmware alone. When the upload is deleted the link is
-- cleared but the row keeps counting until it ages out — so deleting and re-uploading cannot reset the
-- per-network limits. The row carries no user id. Retention (gc-blobs): an unlinked row is deleted once it is
-- older than the longest limit window (30 days); a linked row lives as long as its upload (≤ 180 days) and is
-- then unlinked and deleted the same way.
create table if not exists public.editor_cache_ip_usage (
  id          bigint      generated always as identity primary key,
  ip_key      text        not null check (ip_key ~ '^[0-9a-f]{64}$'),
  upload_id   uuid        references public.editor_cache_uploads(id) on delete set null,
  bytes       integer     check (bytes is null or bytes > 0),   -- real size once the upload completed; null before
  created_at  timestamptz not null default now()
);

create index if not exists editor_cache_ip_usage_key_created_idx
  on public.editor_cache_ip_usage (ip_key, created_at desc);
create index if not exists editor_cache_ip_usage_upload_idx
  on public.editor_cache_ip_usage (upload_id);
create index if not exists editor_cache_ip_usage_created_idx
  on public.editor_cache_ip_usage (created_at);

alter table public.editor_cache_ip_usage enable row level security;
revoke all on public.editor_cache_ip_usage from anon, authenticated;

-- ───────────────────────────── bucket ─────────────────────────────
-- Private, and NO storage.objects policy for it: clients can neither upload, list, read nor delete here except
-- through a signed upload URL the edge function hands out (create-only, one path). Re-asserted on conflict so a
-- pre-existing bucket cannot keep a stale/public configuration.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('editor-caches', 'editor-caches', false, 4194304, array['application/octet-stream'])
on conflict (id) do update set
  public             = false,
  file_size_limit    = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

-- ───────────────────────────── reserve ─────────────────────────────
-- Atomic reservation, serialized per uploader and per network key (advisory locks, always taken in that order,
-- in the two-key form so they cannot collide with any other lock key). In order:
--   1. same uploader, same sha256: complete -> deduped. Pending -> exactly like reserve_diagnostic_capture:
--      object already there -> as is (finalize only); no object -> refresh the announced bytes (+ consent);
--      older than p_pending_max_age_seconds -> recreated (new row id).
--   2. another uploader already completed the same (model, firmware, sha256) -> (null, 'complete', true): no
--      row, no object (an identical file is not counted twice toward coverage).
--   3. coverage state 'covered' or 'closed' -> XQ003 editor_cache_not_wanted.
--   4. the uploader already has p_per_firmware_max rows for (model, firmware) -> XQ004 editor_cache_firmware_limit.
--   5. uploader rate limit XQ001 / byte quota XQ002 (pending charged at the upload cap) — the diagnostic logic.
--   6. network rate limit XQ005 / byte quota XQ006 — the same logic over editor_cache_ip_usage (anonymous ids
--      are free to mint, so this is the limit that actually binds an abuser).
-- Limit errors carry the retry seconds in DETAIL. A refresh (step 1) is the same upload: no new rate slot and no
-- per-firmware check, steps 2–3 use the STORED row's model/firmware (not the repeat request's claim), and both
-- byte quotas are re-checked with the refreshed size.
create or replace function public.reserve_editor_cache_upload(
  p_user_id                 uuid,
  p_ip_key                  text,
  p_model                   integer,
  p_device_firmware         text,
  p_file_version            text,
  p_content_version         text,
  p_file_name               text,
  p_sha256                  text,
  p_bytes                   integer,
  p_redaction               jsonb,
  p_summary                 jsonb,
  p_app                     jsonb,
  p_consent_at              timestamptz,
  p_consent_version         integer,
  p_max_per_window          integer default 5,
  p_window_seconds          integer default 3600,
  p_quota_bytes             bigint  default 20971520,   -- 20 MiB
  p_quota_window_seconds    integer default 2592000,    -- 30 days
  p_pending_charge_bytes    bigint  default 4194304,    -- an unconfirmed reservation counts at the 4 MiB cap
  p_pending_max_age_seconds integer default 72000,      -- 20 h; keep below gc-blobs' 24 h pending sweep
  p_per_firmware_max        integer default 2,
  p_ip_max_per_window       integer default 5,
  p_ip_quota_bytes          bigint  default 20971520    -- 20 MiB
) returns table (row_id uuid, row_status text, deduped boolean)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_existing public.editor_cache_uploads%rowtype;
  v_refresh  boolean := false;   -- own pending row without an object: refresh its announced size
  v_deleted  integer;
  v_new_id   uuid;
  v_model    integer;              -- the (model, firmware) this request is about (the stored row's on a refresh)
  v_fw       text;
  v_state    text;
  v_n        integer;
  v_oldest   timestamptz;
  v_used     bigint;
  v_need     bigint;
  v_freed    bigint;
  v_retry    integer;
  v_rec      record;
begin
  if p_ip_key is null or p_ip_key !~ '^[0-9a-f]{64}$' then
    raise exception 'editor_cache_invalid_network_key' using errcode = '22023';
  end if;

  perform pg_advisory_xact_lock(hashtext('editor-cache:user'), hashtext(p_user_id::text));
  perform pg_advisory_xact_lock(hashtext('editor-cache:ip'), hashtext(p_ip_key));

  -- 1. Own dedup.
  select * into v_existing
    from public.editor_cache_uploads u
   where u.user_id = p_user_id and u.sha256 = p_sha256;
  if found then
    if v_existing.status = 'complete' then
      return query select v_existing.id, v_existing.status, true;
      return;
    end if;

    if v_existing.created_at < now() - make_interval(secs => p_pending_max_age_seconds) then
      -- Too old to hand out an upload URL for: recreate. (Only if still pending; a concurrent self-delete or
      -- sweep may have removed it, a finalize cannot — it takes the same uploader lock.)
      delete from public.editor_cache_uploads u where u.id = v_existing.id and u.status = 'pending';
      get diagnostics v_deleted = row_count;
      if v_deleted = 0 then
        select * into v_existing
          from public.editor_cache_uploads u
         where u.user_id = p_user_id and u.sha256 = p_sha256;
        if found then
          return query select v_existing.id, v_existing.status, true;
          return;
        end if;
      end if;
      -- fall through: reserve as a new upload
    elsif exists (
      select 1 from storage.objects o
       where o.bucket_id = 'editor-caches' and o.name = v_existing.object_path
    ) then
      return query select v_existing.id, v_existing.status, true;
      return;
    else
      v_refresh := true;
    end if;
  end if;

  -- A refresh is the stored upload: its own model/firmware decide, not what the repeat request claims.
  if v_refresh then
    v_model := v_existing.model;
    v_fw    := v_existing.device_firmware;
  else
    v_model := p_model;
    v_fw    := p_device_firmware;
  end if;

  -- 2. Cross-uploader dedup: the identical file for the same device firmware is already in.
  if exists (
    select 1 from public.editor_cache_uploads u
     where u.user_id <> p_user_id
       and u.model = v_model and u.device_firmware = v_fw
       and u.sha256 = p_sha256 and u.status = 'complete'
  ) then
    if v_refresh then
      -- our own reservation for it is redundant now (no object was uploaded for it)
      delete from public.editor_cache_uploads u where u.id = v_existing.id and u.status = 'pending';
    end if;
    return query select null::uuid, 'complete'::text, true;
    return;
  end if;

  -- 3. Coverage: no longer collecting this firmware.
  select c.state into v_state
    from public.editor_cache_coverage c
   where c.model = v_model and c.device_firmware = v_fw;
  if v_state in ('covered', 'closed') then
    raise exception 'editor_cache_not_wanted' using errcode = 'XQ003';
  end if;

  if not v_refresh then
    -- 4. Per (uploader, model, firmware).
    select count(*) into v_n
      from public.editor_cache_uploads u
     where u.user_id = p_user_id and u.model = v_model and u.device_firmware = v_fw;
    if v_n >= p_per_firmware_max then
      raise exception 'editor_cache_firmware_limit' using errcode = 'XQ004';
    end if;

    -- 5a. Uploader rate limit over the newest p_max_per_window rows inside the window.
    select count(*), min(t.created_at) into v_n, v_oldest
      from (
        select u.created_at
          from public.editor_cache_uploads u
         where u.user_id = p_user_id
           and u.created_at > now() - make_interval(secs => p_window_seconds)
         order by u.created_at desc
         limit p_max_per_window
      ) t;
    if v_n >= p_max_per_window then
      v_retry := greatest(1, ceil(extract(epoch from (v_oldest + make_interval(secs => p_window_seconds) - now())))::integer);
      raise exception 'editor_cache_rate_limited' using errcode = 'XQ001', detail = v_retry::text;
    end if;

    -- 6a. Network rate limit (counter rows outlive deleted uploads).
    select count(*), min(t.created_at) into v_n, v_oldest
      from (
        select l.created_at
          from public.editor_cache_ip_usage l
         where l.ip_key = p_ip_key
           and l.created_at > now() - make_interval(secs => p_window_seconds)
         order by l.created_at desc
         limit p_ip_max_per_window
      ) t;
    if v_n >= p_ip_max_per_window then
      v_retry := greatest(1, ceil(extract(epoch from (v_oldest + make_interval(secs => p_window_seconds) - now())))::integer);
      raise exception 'editor_cache_network_rate_limited' using errcode = 'XQ005', detail = v_retry::text;
    end if;
  end if;

  -- 5b. Uploader byte quota: complete rows count their real size, pending rows the full cap. A refreshed row is
  --     excluded (it is re-counted as the incoming request). Retry hint: a complete row stops counting when it
  --     leaves the window, a pending one when gc-blobs removes it (24 h) or it is finalized.
  select coalesce(sum(case when u.status = 'pending' then p_pending_charge_bytes else u.bytes end), 0) into v_used
    from public.editor_cache_uploads u
   where u.user_id = p_user_id
     and u.created_at > now() - make_interval(secs => p_quota_window_seconds)
     and (not v_refresh or u.id <> v_existing.id);
  if v_used + p_bytes > p_quota_bytes then
    v_need  := v_used + p_bytes - p_quota_bytes;
    v_retry := p_quota_window_seconds;
    v_freed := 0;
    for v_rec in
      select case when u.status = 'pending' then p_pending_charge_bytes else u.bytes end as charge,
             case when u.status = 'pending'
                  then u.created_at + make_interval(secs => 86400)
                  else u.created_at + make_interval(secs => p_quota_window_seconds)
             end as frees_at
        from public.editor_cache_uploads u
       where u.user_id = p_user_id
         and u.created_at > now() - make_interval(secs => p_quota_window_seconds)
         and (not v_refresh or u.id <> v_existing.id)
       order by 2 asc
    loop
      v_freed := v_freed + v_rec.charge;
      if v_freed >= v_need then
        v_retry := greatest(1, ceil(extract(epoch from (v_rec.frees_at - now())))::integer);
        exit;
      end if;
    end loop;
    raise exception 'editor_cache_quota_exceeded' using errcode = 'XQ002', detail = v_retry::text;
  end if;

  -- 6b. Network byte quota: a counter linked to a pending upload counts the cap, one with a recorded size its
  --     size, one whose upload was deleted before it completed nothing (like a swept diagnostic reservation).
  select coalesce(sum(case when l.bytes is not null then l.bytes
                           when u.status = 'pending' then p_pending_charge_bytes
                           else 0 end), 0) into v_used
    from public.editor_cache_ip_usage l
    left join public.editor_cache_uploads u on u.id = l.upload_id
   where l.ip_key = p_ip_key
     and l.created_at > now() - make_interval(secs => p_quota_window_seconds)
     and (not v_refresh or l.upload_id is distinct from v_existing.id);
  if v_used + p_bytes > p_ip_quota_bytes then
    v_need  := v_used + p_bytes - p_ip_quota_bytes;
    v_retry := p_quota_window_seconds;
    v_freed := 0;
    for v_rec in
      select case when l.bytes is not null then l.bytes
                  when u.status = 'pending' then p_pending_charge_bytes
                  else 0 end as charge,
             case when l.bytes is null and u.status = 'pending'
                  then u.created_at + make_interval(secs => 86400)
                  else l.created_at + make_interval(secs => p_quota_window_seconds)
             end as frees_at
        from public.editor_cache_ip_usage l
        left join public.editor_cache_uploads u on u.id = l.upload_id
       where l.ip_key = p_ip_key
         and l.created_at > now() - make_interval(secs => p_quota_window_seconds)
         and (not v_refresh or l.upload_id is distinct from v_existing.id)
       order by 2 asc
    loop
      v_freed := v_freed + v_rec.charge;
      if v_freed >= v_need then
        v_retry := greatest(1, ceil(extract(epoch from (v_rec.frees_at - now())))::integer);
        exit;
      end if;
    end loop;
    raise exception 'editor_cache_network_quota_exceeded' using errcode = 'XQ006', detail = v_retry::text;
  end if;

  if v_refresh then
    update public.editor_cache_uploads u
       set bytes = p_bytes, consent_at = p_consent_at, consent_version = p_consent_version
     where u.id = v_existing.id;
    return query select v_existing.id, v_existing.status, true;
    return;
  end if;

  insert into public.editor_cache_uploads
    (user_id, model, device_firmware, file_version, content_version, file_name, sha256, bytes,
     redaction, summary, app, consent_at, consent_version, status, object_path)
  values
    (p_user_id, p_model, p_device_firmware, p_file_version, p_content_version, p_file_name, p_sha256, p_bytes,
     coalesce(p_redaction, '{}'::jsonb), coalesce(p_summary, '{}'::jsonb), coalesce(p_app, '{}'::jsonb),
     p_consent_at, p_consent_version, 'pending', p_user_id::text || '/' || p_sha256 || '.cache')
  returning id into v_new_id;

  insert into public.editor_cache_ip_usage (ip_key, upload_id) values (p_ip_key, v_new_id);

  return query select v_new_id, 'pending'::text, false;
end;
$$;

revoke execute on function public.reserve_editor_cache_upload(uuid, text, integer, text, text, text, text, text, integer, jsonb, jsonb, jsonb, timestamptz, integer, integer, integer, bigint, integer, bigint, integer, integer, integer, bigint)
  from public, anon, authenticated;
grant execute on function public.reserve_editor_cache_upload(uuid, text, integer, text, text, text, text, text, integer, jsonb, jsonb, jsonb, timestamptz, integer, integer, integer, bigint, integer, bigint, integer, integer, integer, bigint)
  to service_role;

-- ───────────────────────────── complete ─────────────────────────────
-- Called by finalize AFTER the edge function verified the stored object (size, sha256, structure, redaction).
-- One transaction: pending -> complete with the real size and the verified header version, the network counter
-- gets the real size, and — for a version-matched upload — coverage is recomputed: distinct uploaders (counted
-- at most once per network key) with a complete, version-matched upload of this (model, firmware) (reserved
-- after a maintainer reopen, if any), kept as a high-water mark; 'collecting' becomes 'covered' at p_threshold,
-- 'covered'/'closed' stay as they are.
-- Returns no row when the upload does not exist (for this uploader); `covered` = the firmware is no longer
-- collecting (covered or closed).
create or replace function public.complete_editor_cache_upload(
  p_user_id         uuid,
  p_row_id          uuid,
  p_bytes           integer,
  p_content_version text    default null,
  p_threshold       integer default 2
) returns table (row_status text, covered boolean)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row   public.editor_cache_uploads%rowtype;
  v_since timestamptz;
  v_users integer;
  v_state text;
begin
  -- Same uploader lock as reserve: a reservation never sees a row change status under it.
  perform pg_advisory_xact_lock(hashtext('editor-cache:user'), hashtext(p_user_id::text));

  update public.editor_cache_uploads u
     set status = 'complete',
         bytes = p_bytes,
         content_version = coalesce(p_content_version, u.content_version)
   where u.id = p_row_id and u.user_id = p_user_id and u.status = 'pending'
  returning * into v_row;

  if not found then
    -- Already complete (a repeat finalize) or gone.
    select * into v_row from public.editor_cache_uploads u where u.id = p_row_id and u.user_id = p_user_id;
    if not found then
      return;
    end if;
    select c.state into v_state
      from public.editor_cache_coverage c
     where c.model = v_row.model and c.device_firmware = v_row.device_firmware;
    return query select v_row.status, coalesce(v_state <> 'collecting', false);
    return;
  end if;

  update public.editor_cache_ip_usage l set bytes = p_bytes where l.upload_id = p_row_id;

  if v_row.version_match then
    -- Serialize coverage updates per (model, firmware) across uploaders.
    perform pg_advisory_xact_lock(hashtext('editor-cache:coverage'), hashtext(v_row.model::text || '/' || v_row.device_firmware));
    select c.reopened_at into v_since
      from public.editor_cache_coverage c
     where c.model = v_row.model and c.device_firmware = v_row.device_firmware;
    -- Distinct uploaders, but never more than distinct networks: anonymous ids are free to mint, so two ids
    -- from one network count once and cannot cover a firmware alone. (Each upload's network key is the counter
    -- row its reservation created; an upload without one does not count.)
    select least(count(distinct u.user_id), count(distinct l.ip_key)) into v_users
      from public.editor_cache_uploads u
      join public.editor_cache_ip_usage l on l.upload_id = u.id
     where u.model = v_row.model and u.device_firmware = v_row.device_firmware
       and u.status = 'complete' and u.version_match
       and (v_since is null or u.created_at >= v_since);
    insert into public.editor_cache_coverage as c (model, device_firmware, contributors, state, updated_at)
    values (v_row.model, v_row.device_firmware, v_users,
            case when v_users >= p_threshold then 'covered' else 'collecting' end, now())
    on conflict (model, device_firmware) do update set
      contributors = greatest(c.contributors, excluded.contributors),
      state = case when c.state = 'collecting' and greatest(c.contributors, excluded.contributors) >= p_threshold
                   then 'covered' else c.state end,
      updated_at = now()
    returning c.state into v_state;
  else
    select c.state into v_state
      from public.editor_cache_coverage c
     where c.model = v_row.model and c.device_firmware = v_row.device_firmware;
  end if;

  return query select 'complete'::text, coalesce(v_state <> 'collecting', false);
end;
$$;

revoke execute on function public.complete_editor_cache_upload(uuid, uuid, integer, text, integer)
  from public, anon, authenticated;
grant execute on function public.complete_editor_cache_upload(uuid, uuid, integer, text, integer)
  to service_role;

-- ───────────────────────────── maintainer: set coverage ─────────────────────────────
-- select public.set_editor_cache_coverage(<model>, '<firmware>', 'covered' | 'closed' | 'collecting');
--   covered    stop asking (e.g. a firmware the maintainer already has)
--   closed     never collect (e.g. a beta)
--   collecting reopen: contributors reset to 0 and only uploads reserved from now on count toward 'covered'
-- Service role only (SQL editor / REST rpc with the service key); never callable by clients.
create or replace function public.set_editor_cache_coverage(
  p_model           integer,
  p_device_firmware text,
  p_state           text
) returns public.editor_cache_coverage
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.editor_cache_coverage%rowtype;
  v_fw  text;
begin
  if p_state is null or p_state not in ('collecting', 'covered', 'closed') then
    raise exception 'state must be collecting, covered or closed' using errcode = '22023';
  end if;
  if p_model is null or p_model < 0 or p_model > 255 then
    raise exception 'model must be 0..255' using errcode = '22023';
  end if;
  -- Normalize the firmware the way devices report it (`major.minor` without leading zeros: '32.06' -> '32.6'),
  -- so a hand-typed value matches the keys uploads use.
  if p_device_firmware is null or p_device_firmware !~ '^\d{1,3}\.\d{1,3}$' then
    raise exception 'firmware must look like 13.0' using errcode = '22023';
  end if;
  v_fw := split_part(p_device_firmware, '.', 1)::integer::text || '.' || split_part(p_device_firmware, '.', 2)::integer::text;
  insert into public.editor_cache_coverage as c (model, device_firmware, contributors, state, reopened_at, updated_at)
  values (p_model, v_fw, 0, p_state, case when p_state = 'collecting' then now() end, now())
  on conflict (model, device_firmware) do update set
    state        = excluded.state,
    contributors = case when excluded.state = 'collecting' then 0 else c.contributors end,
    reopened_at  = case when excluded.state = 'collecting' then now() else c.reopened_at end,
    updated_at   = now()
  returning c.* into v_row;
  return v_row;
end;
$$;

revoke execute on function public.set_editor_cache_coverage(integer, text, text) from public, anon, authenticated;
grant execute on function public.set_editor_cache_coverage(integer, text, text) to service_role;

-- ───────────────────────────── service_role grants ─────────────────────────────
-- uploads: finalize/list read, delete-account + self-delete + gc-blobs delete, the maintainer reads/deletes.
-- Rows are created and completed only by the definer functions above, so no INSERT; UPDATE is kept for the
-- maintainer (e.g. extending expires_at on request), as for diagnostic_captures.
grant select, update, delete on public.editor_cache_uploads to service_role;
-- coverage: the public status GET reads it; the maintainer may edit it directly as well as through the function.
grant select, insert, update on public.editor_cache_coverage to service_role;
-- network counters: gc-blobs prunes old rows; the maintainer may inspect them. Written only by the functions.
grant select, delete on public.editor_cache_ip_usage to service_role;
