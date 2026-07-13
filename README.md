# Axis Cloud (sync backend)

Optional cloud sync for [Axis](https://github.com/sKuhLight/Axis): backs up your config and presets,
with version history, across devices. **Source-available + self-hostable for noncommercial use** —
point Axis at the hosted service (a supporter convenience) *or* run your own Supabase project.

## What it is
A **Supabase project** (Postgres + Auth + Storage) — no custom server. Per-user isolation via
Row-Level Security, so the client talks to it directly with the publishable/anon key and only ever
sees its own data.

```
supabase/
  config.toml                 # CLI config (auth/storage); no secrets
  migrations/                 # versioned schema (run in order)
    20260630120000_init.sql   # documents, preset_versions, backups, subscriptions + preset-blobs bucket
    20260713120000_device_profiles.sql  # global, public-read device-definition profile store
.env.example                  # SUPABASE_URL / SUPABASE_ANON_KEY / AXIS_CLOUD (copy to .env)
```

Tables: `documents` (config — tags, collections, favorites, saved filters, layouts, swipe, settings),
`preset_versions` + `backups` (metadata), `subscriptions` (supporter gating), and a private
`preset-blobs` Storage bucket.

## How sync works (design)
- **Local stays the source of truth.** ForgeFX's local store (`server/src/store.ts`) is authoritative;
  the cloud is a mirror you opt into.
- **ForgeFX is the sync client.** When `AXIS_CLOUD` + `SUPABASE_URL` + `SUPABASE_ANON_KEY` are set and a
  user is logged in, ForgeFX pushes/pulls changed records. **Last-write-wins by `updated_at`** for
  documents; preset `.syx` blobs (already brotli-compressed, ~6×) go to Storage by `blob_path`.
- **User picks what syncs** (per scope): presets, scenes/setlists, footswitch/controllers, settings. The
  device-derived preset *cache* never syncs — it's cheaper to rebuild locally.
- **Auth:** email/password to start (no redirect; works headless from ForgeFX). OAuth later.

## Supporter gating (provider-neutral)
Hosted cloud + early-access features are a **supporter** tier (planned via **Patreon** — no in-app
billing to build or maintain). A Patreon account link sets `subscriptions.plan` for that user; Axis
reads only its own row. The `source` column keeps it provider-neutral so the backend can switch later.
Self-hosters skip this entirely — run your own project and everything is unlocked.

## Device-definition profile store (shared, not user data)
A **global, cross-user** store for derived *device-definition profiles* (`BuiltCache` JSON docs, produced
by ForgeFX's on-connect self-describe walk / editor-cache parse). A profile is **identical for every
device of the same model on the same firmware**, so it is shared: the first user on a new firmware
uploads it, and everyone else downloads it instead of rebuilding. These are **derived tables only**
(param ranges, model rosters, enum overrides, cab-IR names, section maps) — **never raw Fractal editor
files and never any preset content.**

- **Table `device_profiles`** (public read via RLS; **no client write policy** — writes are service-role
  only). Keyed by `(model, firmware, content_hash)` with a size guard; `content_hash` is the sha256 of the
  canonical profile JSON, computed **server-side** (a client-supplied hash is never trusted).
- **Edge function `device-profiles`** (JWT verification off at the platform layer so GET is public):
  - `GET ?model=<int>&firmware=<string>` → newest matching profile + metadata (`404` if none;
    `Cache-Control: public, max-age=300`).
  - `POST { model, firmware, source, profile }` → **requires a valid user JWT**. Validates `model`
    (int 1..255), `firmware` (`^\d+\.\d+`), `source` (`live-walk` | `editor-cache`) and the profile's
    plausible `BuiltCache` shape, caps the body (~6 MB), computes the hash, and inserts with the service
    role. An identical existing profile returns `{ deduped: true }`; a user may add at most 10 new
    profiles per hour.
- **Key discipline (ForgeFX side):** profiles are keyed `<model-hex>_<major>p<minor>` (e.g. FM3 fw 12.0
  → `11_12p0`); this backend stores the `model` byte as an integer (`0x11` = 17) and `firmware` as a
  string (`"12.0"`).

## Gating (so it never ships dark)
The entire sync layer is behind `AXIS_CLOUD=1`. With it unset, ForgeFX loads no cloud code and Axis
shows no login — release builds do not set it.

## Self-host
With the [Supabase CLI](https://supabase.com/docs/guides/local-development):

```bash
# 1. Create a project at supabase.com (or run `supabase start` for a local stack)
supabase link --project-ref YOUR-PROJECT-REF
supabase db push                      # applies migrations/

# 2. Point ForgeFX at it
cp .env.example .env                  # fill in SUPABASE_URL + SUPABASE_ANON_KEY
```

Then run ForgeFX with those env vars (+ `AXIS_CLOUD=1`). Configure SMTP in the Supabase dashboard if you
want email confirmations.

> **Secrets:** the publishable/anon key is safe to expose (RLS protects every row). The service-role
> key, DB password, SMTP creds, and the future Patreon client secret must **never** be committed — keep
> them in the Supabase dashboard and your CI secrets.

## Status
- [x] Schema + RLS + Storage policy
- [x] ForgeFX sync client (supabase-js, gated by `AXIS_CLOUD`)
- [x] Axis login + per-scope sync toggles + cloud preset viewer / version restore
- [x] Global device-definition profile store (`device_profiles` + `device-profiles` edge fn)
- [ ] Patreon account link → `subscriptions` (hosted supporter tier)

## License
Copyright © 2026 sKuhLight. Licensed under the **PolyForm Noncommercial License 1.0.0** — see
[`LICENSE.md`](./LICENSE.md). In short: you may use, modify, and self-host this for **any noncommercial
purpose** (personal use, research, non-profits), but **not for commercial advantage or monetary
compensation**. Commercial rights — including the hosted supporter service — are reserved by the author.

> This is *source-available*, not OSI "open source" (an OSI license would have to permit commercial use).
> "Noncommercial" can be a gray area for edge cases — if you want to use Axis Cloud commercially, ask.
