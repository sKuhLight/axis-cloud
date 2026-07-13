-- Global device-definition profile store (AXISCLOUD-2, part of the META-22 device-definition cloud
-- pipeline). Unlike everything else in this backend, these rows are NOT user data: a "profile" is a
-- derived `BuiltCache` JSON doc (ForgeFX server/src/services/deviceCache.ts → forgefx-midi buildCache)
-- that is byte-identical for every device of the same model on the same firmware. The first user on a
-- new firmware uploads it; everyone else just downloads it. So this table is PUBLIC-READ and shared
-- across all users — no auth.uid() scoping, no RLS ownership.
--
-- Profiles are DERIVED tables only (ranges, rosters, enum overrides, cab-IR names, section maps). They
-- carry no preset content and no raw Fractal editor files — never store either here.
--
-- Writes go EXCLUSIVELY through the `device-profiles` edge function (service role): it verifies a user
-- JWT, validates + size-caps the body, computes the content hash server-side, and rate-limits. There
-- are deliberately NO insert/update/delete policies, so the anon/authenticated key can only read.

create table if not exists public.device_profiles (
  id            uuid        primary key default gen_random_uuid(),
  model         smallint    not null,                 -- Fractal model byte (e.g. 0x11 = 17 for FM3)
  firmware      text        not null,                 -- firmware version string (e.g. '12.0')
  content_hash  text        not null,                 -- sha256 hex of the canonical profile JSON (server-computed)
  profile       jsonb       not null,                 -- the derived BuiltCache doc
  source        text        not null check (source in ('live-walk', 'editor-cache')),
  record_count  integer,                              -- profile.meta.recordCount (convenience/observability)
  created_by    uuid        references auth.users(id) on delete set null,
  created_at    timestamptz not null default now(),
  -- one row per (model, firmware, exact content); identical re-uploads dedup on this
  unique (model, firmware, content_hash),
  -- size guard: bound a single profile well under the ~6 MB edge-function body cap (pg_column_size is
  -- awkward inside a CHECK, so bound the text projection at 8 MiB)
  constraint device_profiles_size_guard check (octet_length(profile::text) <= 8388608)
);

-- Newest-first lookup for a given (model, firmware) — the read path's only query shape.
create index if not exists device_profiles_model_fw_created_idx
  on public.device_profiles (model, firmware, created_at desc);

alter table public.device_profiles enable row level security;

-- Public read: any client (logged in or not) may fetch profiles — they are shared, non-sensitive
-- derived data. No INSERT/UPDATE/DELETE policies exist: writes are service-role-only via the edge fn.
create policy "device profiles are public" on public.device_profiles
  for select to anon, authenticated using (true);
