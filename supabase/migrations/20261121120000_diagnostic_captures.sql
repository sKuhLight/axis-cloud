-- Diagnostic captures (MT): an opt-in, in-product "device diagnostic" run produces a redacted JSON
-- bundle (wire log + probe results, schema 1) that a signed-in user may upload for analysis. Unlike
-- every other table here this is NOT per-user-readable data: the uploader can neither list nor read
-- back its own captures — only the maintainer (service role) reads them.
--
-- Writes go EXCLUSIVELY through the `diagnostic-captures` edge function (service role): it verifies the
-- user JWT, size-caps + gunzips + validates the bundle, rate-limits, stores the ORIGINAL gzip object in
-- the private `diagnostic-captures` bucket at <user_id>/<capture_id>.json.gz and inserts the row below.
--
-- Access model — deny by default, twice over:
--   * RLS is enabled and there is deliberately NO policy for anon/authenticated (RLS on + no policy =
--     deny all), and
--   * table privileges are revoked from anon/authenticated as defence in depth, so even a future
--     mistaken policy cannot expose a row through PostgREST.
-- The service role bypasses RLS (and keeps its grants), which is how the edge function writes and how
-- the maintainer reads.

create table if not exists public.diagnostic_captures (
  id           uuid        primary key default gen_random_uuid(),
  user_id      uuid        not null references auth.users(id) on delete cascade,
  capture_id   text        not null,                     -- the bundle's own id (bundle.id); unique per user
  model        integer     not null,                     -- Fractal model byte (bundle.device.model)
  firmware     text,                                     -- bundle.device.firmware; null when unknown
  app          jsonb       not null default '{}'::jsonb, -- version stamps only: { forgefx, codec, axis? }
  state        text        not null,                     -- bundle.state: done | failed | cancelled (| unknown)
  bytes        integer     not null,                     -- size of the stored gzip object
  object_path  text        not null,                     -- <user_id>/<capture_id>.json.gz in the bucket
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null default now() + interval '180 days',
  -- Idempotency: re-uploading the same bundle returns the existing row instead of a second copy.
  unique (user_id, capture_id),
  -- capture_id becomes part of a storage object name, so it must be path-safe (the edge function
  -- enforces the same pattern; this is the backstop).
  constraint diagnostic_captures_capture_id_format check (capture_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'),
  -- Everything (delete-account, retention GC) relies on objects living under <user_id>/.
  constraint diagnostic_captures_object_path_format check (object_path = user_id::text || '/' || capture_id || '.json.gz'),
  constraint diagnostic_captures_bytes_positive check (bytes > 0)
);

-- Per-user lookups: the rate-limit query (user's newest rows) and account deletion.
create index if not exists diagnostic_captures_user_created_idx
  on public.diagnostic_captures (user_id, created_at desc);

-- Retention sweep (gc-blobs): rows past expires_at.
create index if not exists diagnostic_captures_expires_at_idx
  on public.diagnostic_captures (expires_at);

alter table public.diagnostic_captures enable row level security;
-- No policies on purpose: no select/insert/update/delete for anon or authenticated.
revoke all on public.diagnostic_captures from anon, authenticated;

-- ── Storage: private bucket for the gzip bundles ──
-- Not public, and NO storage.objects policy for this bucket: clients cannot upload, list, read or delete
-- objects here (the policies other buckets define are all scoped by bucket_id). The edge function
-- uploads with the service role, which bypasses storage RLS. The bucket-level limits mirror the edge
-- function's caps: 25 MiB compressed per object, gzip only.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('diagnostic-captures', 'diagnostic-captures', false, 26214400, array['application/gzip'])
on conflict (id) do nothing;
