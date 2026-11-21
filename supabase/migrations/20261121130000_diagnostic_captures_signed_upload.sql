-- Diagnostic captures, step 2: signed-upload flow (supersedes the "edge function receives the gzip"
-- design described in 20261121120000_diagnostic_captures.sql — that migration was never deployed; this
-- one adjusts its objects instead of rewriting it, as migrations are immutable).
--
-- Why the flow changed: an edge function must not read and parse a client-supplied gzip (a tiny gzip can
-- expand into a structure that exhausts the worker's memory), and hosted edge functions cap the request
-- body far below the 25 MiB bundle limit (see the ~6 MB note in 20260713120000_device_profiles.sql). So the
-- edge function now only handles SMALL JSON requests:
--
--   1. reserve  — authenticate, validate, then reserve a row atomically (rate limit + byte quota + dedup,
--                 below) and hand out a signed upload URL for <user_id>/<capture_id>.json.gz;
--   2. the client uploads the gzip straight to the private bucket (the bucket enforces 25 MiB and
--      application/gzip); nothing is parsed server-side;
--   3. finalize — the edge function checks the object (exists, size, gzip magic via a 2-byte range read)
--      and flips the row from 'pending' to 'complete'.
--
-- A row therefore has a lifecycle: 'pending' (reserved, upload not confirmed) → 'complete'. gc-blobs removes
-- pending rows (and their objects) after 24 h.

-- ── status ──
-- Existing rows (none in any deployed database, but a local dev stack may have some) were stored by the
-- previous flow, i.e. complete: backfill them as 'complete', then make 'pending' the default for new rows.
alter table public.diagnostic_captures
  add column if not exists status text not null default 'complete'
  constraint diagnostic_captures_status_check check (status in ('pending', 'complete'));
alter table public.diagnostic_captures alter column status set default 'pending';

-- gc-blobs' stale-pending sweep (tiny: pending rows are short-lived).
create index if not exists diagnostic_captures_pending_idx
  on public.diagnostic_captures (created_at) where status = 'pending';

-- ── bucket: re-assert the settings even if the bucket already exists (`on conflict do nothing` in the
--    first migration would silently keep a stale/public configuration) ──
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('diagnostic-captures', 'diagnostic-captures', false, 26214400, array['application/gzip'])
on conflict (id) do update set
  public             = false,
  file_size_limit    = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

-- ── atomic reservation: dedup + rate limit + byte quota + insert, serialized per user ──
-- The edge function used to count-then-insert, which parallel requests could race past. Here everything
-- happens under a per-user advisory lock inside one transaction, so the limits hold under concurrency.
--
--   · dedup:  an existing (user_id, capture_id) row is returned as-is (deduped = true) and does NOT consume
--             a slot or quota — a retry after a lost response is always safe.
--   · rate:   at most p_max_per_window NEW rows per rolling p_window_seconds (pending ones count: a slot is
--             consumed by the reservation, not by a successful upload).
--   · quota:  the bytes announced by a user's rows of the last p_quota_window_seconds plus this one must not
--             exceed p_quota_bytes.
-- Limits raise a custom SQLSTATE the edge function maps to HTTP 429; DETAIL carries the seconds until the
-- limit would admit this request again:
--   XQ001  diagnostic_rate_limited
--   XQ002  diagnostic_quota_exceeded
-- SECURITY DEFINER (it must write a table clients have no privileges on), pinned search_path, and EXECUTE
-- is granted to service_role ONLY (the edge function). Do not loosen — same rule as the quota functions.
create or replace function public.reserve_diagnostic_capture(
  p_user_id              uuid,
  p_capture_id           text,
  p_model                integer,
  p_firmware             text,
  p_app                  jsonb,
  p_state                text,
  p_bytes                integer,
  p_max_per_window       integer default 5,
  p_window_seconds       integer default 3600,
  p_quota_bytes          bigint  default 209715200,   -- 200 MiB
  p_quota_window_seconds integer default 2592000      -- 30 days
) returns table (row_id uuid, row_status text, deduped boolean)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_existing public.diagnostic_captures%rowtype;
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
    return query select v_existing.id, v_existing.status, true;
    return;
  end if;

  -- Rate limit over the newest p_max_per_window rows inside the window. If they are all there, the slot
  -- frees up when the oldest of them leaves the window.
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

  -- Byte quota over the quota window.
  select coalesce(sum(dc.bytes), 0) into v_used
    from public.diagnostic_captures dc
   where dc.user_id = p_user_id
     and dc.created_at > now() - make_interval(secs => p_quota_window_seconds);
  if v_used + p_bytes > p_quota_bytes then
    -- Retry hint: walk the user's rows oldest-first until enough bytes have aged out. (If the request alone
    -- exceeds the quota it never fits: report the full window.)
    v_need  := v_used + p_bytes - p_quota_bytes;
    v_retry := p_quota_window_seconds;
    for v_rec in
      select dc.bytes, dc.created_at
        from public.diagnostic_captures dc
       where dc.user_id = p_user_id
         and dc.created_at > now() - make_interval(secs => p_quota_window_seconds)
       order by dc.created_at asc
    loop
      v_freed := v_freed + v_rec.bytes;
      if v_freed >= v_need then
        v_retry := greatest(1, ceil(extract(epoch from (v_rec.created_at + make_interval(secs => p_quota_window_seconds) - now())))::integer);
        exit;
      end if;
    end loop;
    raise exception 'diagnostic_quota_exceeded' using errcode = 'XQ002', detail = v_retry::text;
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

revoke execute on function public.reserve_diagnostic_capture(uuid, text, integer, text, jsonb, text, integer, integer, integer, bigint, integer)
  from public, anon, authenticated;
grant execute on function public.reserve_diagnostic_capture(uuid, text, integer, text, jsonb, text, integer, integer, integer, bigint, integer)
  to service_role;
