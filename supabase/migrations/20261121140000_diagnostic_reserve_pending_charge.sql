-- Diagnostic captures, step 3: close the quota bypass in reserve_diagnostic_capture and tighten how a
-- repeat reservation treats a pending row. Replaces the function from 20261121130000 (new signature, so the
-- old one is dropped); that migration is left as is — migrations are immutable.
--
-- (Wording note on 20261121130000: its remark that hosted edge functions "cap the request body far below the
-- 25 MiB bundle limit" rests on the ~6 MB note in the device_profiles migration and is UNVERIFIED for
-- 25 MiB. The design does not depend on it: the function never receives the bundle either way.)
--
-- Changes:
--   · quota (S-A): the announced `bytes` is only a claim until finalize checks the object, so an unconfirmed
--     ('pending') reservation is charged at the full upload cap (p_pending_charge_bytes = the bucket's
--     25 MiB), not at what the client said. Otherwise a client could announce 1 byte, upload 25 MiB and never
--     finalize, staying far under the quota. Finalize then records the real size, which frees the difference.
--   · refresh (N-a): a repeat reservation of a pending row whose object has NOT been uploaded refreshes the
--     announced `bytes` (quota re-checked), so a retry with a re-gzipped (different-size) bundle is not stuck
--     failing finalize's size check. If the object is already there, the row is returned unchanged.
--   · recreate (N-c): a pending row older than p_pending_max_age_seconds (default 20 h) is NOT reused or
--     refreshed — it is deleted and reserved afresh (new row id, new created_at; the rate limit and quota
--     apply as for any new reservation) — so a client is never handed an upload URL for a row gc-blobs'
--     24 h pending sweep is about to delete.
--   · retry hint: a pending row frees its quota when gc-blobs removes it (24 h after creation) or when it is
--     finalized, so its hint uses created_at + 24 h instead of the 30-day quota window.

drop function if exists public.reserve_diagnostic_capture(uuid, text, integer, text, jsonb, text, integer, integer, integer, bigint, integer);

create or replace function public.reserve_diagnostic_capture(
  p_user_id                 uuid,
  p_capture_id              text,
  p_model                   integer,
  p_firmware                text,
  p_app                     jsonb,
  p_state                   text,
  p_bytes                   integer,
  p_max_per_window          integer default 5,
  p_window_seconds          integer default 3600,
  p_quota_bytes             bigint  default 209715200,   -- 200 MiB
  p_quota_window_seconds    integer default 2592000,     -- 30 days
  p_pending_charge_bytes    bigint  default 26214400,    -- what an unconfirmed reservation counts: the 25 MiB cap
  p_pending_max_age_seconds integer default 72000        -- 20 h; keep below gc-blobs' 24 h pending sweep
) returns table (row_id uuid, row_status text, deduped boolean)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_existing public.diagnostic_captures%rowtype;
  v_refresh  boolean := false;   -- a fresh pending row without an object: refresh its announced size
  v_deleted  integer;
  v_new_id   uuid;
  v_n        integer;
  v_oldest   timestamptz;
  v_used     bigint;
  v_need     bigint;
  v_freed    bigint := 0;
  v_retry    integer;
  v_rec      record;
begin
  -- Serialize per user: two parallel reservations must not both pass the limits.
  perform pg_advisory_xact_lock(hashtext('diag-reserve:' || p_user_id::text));

  -- Dedup: the same bundle id from the same user is the same capture.
  select * into v_existing
    from public.diagnostic_captures dc
   where dc.user_id = p_user_id and dc.capture_id = p_capture_id;
  if found then
    if v_existing.status = 'complete' then
      return query select v_existing.id, v_existing.status, true;
      return;
    end if;

    if v_existing.created_at < now() - make_interval(secs => p_pending_max_age_seconds) then
      -- Too old to hand out an upload URL for: recreate. (Only if still pending: a finalize may have won.)
      delete from public.diagnostic_captures dc where dc.id = v_existing.id and dc.status = 'pending';
      get diagnostics v_deleted = row_count;
      if v_deleted = 0 then
        select * into v_existing
          from public.diagnostic_captures dc
         where dc.user_id = p_user_id and dc.capture_id = p_capture_id;
        if found then
          return query select v_existing.id, v_existing.status, true;
          return;
        end if;
      end if;
      -- fall through: reserve as a new capture
    elsif exists (
      select 1 from storage.objects o
       where o.bucket_id = 'diagnostic-captures' and o.name = v_existing.object_path
    ) then
      -- The upload is already there; the client only has to finalize. Nothing to change.
      return query select v_existing.id, v_existing.status, true;
      return;
    else
      v_refresh := true;
    end if;
  end if;

  -- Rate limit (a refresh is the same capture, not a new slot) over the newest p_max_per_window rows inside
  -- the window. If they are all there, the slot frees up when the oldest of them leaves the window.
  if not v_refresh then
    select count(*), min(t.created_at) into v_n, v_oldest
      from (
        select dc.created_at
          from public.diagnostic_captures dc
         where dc.user_id = p_user_id
           and dc.created_at > now() - make_interval(secs => p_window_seconds)
         order by dc.created_at desc
         limit p_max_per_window
      ) t;
    if v_n >= p_max_per_window then
      v_retry := greatest(1, ceil(extract(epoch from (v_oldest + make_interval(secs => p_window_seconds) - now())))::integer);
      raise exception 'diagnostic_rate_limited' using errcode = 'XQ001', detail = v_retry::text;
    end if;
  end if;

  -- Byte quota over the quota window: complete rows count their real size, pending rows the full cap. When
  -- refreshing, the row itself is excluded (it is re-counted as the incoming request).
  select coalesce(sum(case when dc.status = 'pending' then p_pending_charge_bytes else dc.bytes end), 0) into v_used
    from public.diagnostic_captures dc
   where dc.user_id = p_user_id
     and dc.created_at > now() - make_interval(secs => p_quota_window_seconds)
     and (not v_refresh or dc.id <> v_existing.id);
  if v_used + p_bytes > p_quota_bytes then
    -- Retry hint: walk the user's rows by when they stop counting until enough bytes have been freed. A
    -- complete row stops counting when it leaves the quota window; a pending one when gc-blobs removes it
    -- (24 h after creation) or it is finalized. (If the request alone exceeds the quota it never fits:
    -- report the full window.)
    v_need  := v_used + p_bytes - p_quota_bytes;
    v_retry := p_quota_window_seconds;
    for v_rec in
      select case when dc.status = 'pending' then p_pending_charge_bytes else dc.bytes end as charge,
             case when dc.status = 'pending'
                  then dc.created_at + make_interval(secs => 86400)
                  else dc.created_at + make_interval(secs => p_quota_window_seconds)
             end as frees_at
        from public.diagnostic_captures dc
       where dc.user_id = p_user_id
         and dc.created_at > now() - make_interval(secs => p_quota_window_seconds)
         and (not v_refresh or dc.id <> v_existing.id)
       order by 2 asc
    loop
      v_freed := v_freed + v_rec.charge;
      if v_freed >= v_need then
        v_retry := greatest(1, ceil(extract(epoch from (v_rec.frees_at - now())))::integer);
        exit;
      end if;
    end loop;
    raise exception 'diagnostic_quota_exceeded' using errcode = 'XQ002', detail = v_retry::text;
  end if;

  if v_refresh then
    update public.diagnostic_captures dc set bytes = p_bytes where dc.id = v_existing.id;
    return query select v_existing.id, v_existing.status, true;
    return;
  end if;

  insert into public.diagnostic_captures
    (user_id, capture_id, model, firmware, app, state, bytes, object_path, status)
  values
    (p_user_id, p_capture_id, p_model, p_firmware, coalesce(p_app, '{}'::jsonb), p_state, p_bytes,
     p_user_id::text || '/' || p_capture_id || '.json.gz', 'pending')
  returning id into v_new_id;

  return query select v_new_id, 'pending'::text, false;
end;
$$;

revoke execute on function public.reserve_diagnostic_capture(uuid, text, integer, text, jsonb, text, integer, integer, integer, bigint, integer, bigint, integer)
  from public, anon, authenticated;
grant execute on function public.reserve_diagnostic_capture(uuid, text, integer, text, jsonb, text, integer, integer, integer, bigint, integer, bigint, integer)
  to service_role;
