-- Axis Cloud — initial schema (open-source, self-hostable). Per-user sync enforced by Row-Level
-- Security: every row is scoped to auth.uid(), so the client may talk to PostgREST directly with the
-- publishable/anon key and still only ever see its own data.
--
-- Mirrors ForgeFX's local store (server/src/store.ts): documents (config), preset_versions, backups.
-- Sync model = last-write-wins by `updated_at` (client epoch ms). Preset .syx blobs live in Storage
-- (already brotli-compressed by ForgeFX), referenced by blob_path.

-- ── config / metadata documents (tags, collections, favorites, savedFilters, layouts, swipe, settings) ──
create table if not exists public.documents (
  user_id    uuid    not null references auth.users(id) on delete cascade,
  collection text    not null,
  id         text    not null,
  data       jsonb   not null,
  updated_at bigint  not null,            -- client epoch ms → LWW
  rev        int     not null default 1,
  deleted    boolean not null default false,
  synced_at  timestamptz not null default now(),
  primary key (user_id, collection, id)
);
alter table public.documents enable row level security;
create policy "documents are private" on public.documents
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- ── preset version snapshots (metadata; the .syx blob is in the `preset-blobs` Storage bucket) ──
create table if not exists public.preset_versions (
  user_id     uuid   not null references auth.users(id) on delete cascade,
  id          text   not null,
  location    int    not null,            -- preset slot (-1 = edit buffer)
  crc         int    not null,            -- content fingerprint
  name        text   not null,
  model       text   not null,
  captured_at bigint not null,
  source      text   not null,            -- manual | auto | backup
  backup_id   text,
  bytes       int    not null,            -- raw .syx size
  stored      int    not null,            -- compressed size
  blob_path   text   not null,            -- {user_id}/{location}/{id}.syx.br
  primary key (user_id, id)
);
alter table public.preset_versions enable row level security;
create policy "versions are private" on public.preset_versions
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- ── full-device backups ──
create table if not exists public.backups (
  user_id    uuid   not null references auth.users(id) on delete cascade,
  id         text   not null,
  created_at bigint not null,
  label      text,
  model      text,
  count      int    not null default 0,
  primary key (user_id, id)
);
alter table public.backups enable row level security;
create policy "backups are private" on public.backups
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- ── supporter gating (set by the Patreon link/webhook later; clients only read their own row) ──
create table if not exists public.subscriptions (
  user_id            uuid primary key references auth.users(id) on delete cascade,
  active             boolean not null default false,
  plan               text,                -- e.g. 'Free' | 'Supporter'
  source             text,                -- 'patreon' (provider-neutral for a future switch)
  current_period_end timestamptz
);
alter table public.subscriptions enable row level security;
create policy "own subscription readable" on public.subscriptions
  for select using (auth.uid() = user_id);

-- ── Storage: private bucket for preset blobs; users may only touch their own {user_id}/… path ──
insert into storage.buckets (id, name, public) values ('preset-blobs', 'preset-blobs', false)
  on conflict (id) do nothing;
create policy "own blobs" on storage.objects
  for all to authenticated
  using (bucket_id = 'preset-blobs' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'preset-blobs' and (storage.foldername(name))[1] = auth.uid()::text);
