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
    20261121120000_diagnostic_captures.sql  # opt-in diagnostic uploads: maintainer-only table + private bucket
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
  - `GET ?model=<int>&firmware=<string>[&schema=<int>]` → newest matching profile + metadata (`404` if
    none; `Cache-Control: public, max-age=300`). `schema` is the profile schema the caller can use
    (`profile.meta.schema`): the newest row **of that schema** is returned, so clients on different
    schemas never hide each other's profiles (`400` unless an integer 1..1000000). Without `schema`
    (older clients) only unstamped rows and schema <= 1 are served. No migration — the filter reads the
    stored profile JSON.
  - `POST { model, firmware, source, profile }` → **requires a valid user JWT**. Validates `model`
    (int 1..255), `firmware` (`^\d+\.\d+`), `source` (`live-walk` | `editor-cache`) and the profile's
    plausible `BuiltCache` shape, caps the body (~6 MB), computes the hash, and inserts with the service
    role. An identical existing profile returns `{ deduped: true }`; a user may add at most 10 new
    profiles per hour.
- **Key discipline (ForgeFX side):** profiles are keyed `<model-hex>_<major>p<minor>` (e.g. FM3 fw 12.0
  → `11_12p0`); this backend stores the `model` byte as an integer (`0x11` = 17) and `firmware` as a
  string (`"12.0"`).

## Diagnostic captures (opt-in, maintainer-only)
A signed-in user can upload the result of Axis's in-product **device diagnostic** (Settings → Debugging) so
the maintainer can analyse how a given model/firmware behaves. It is never sent automatically: the user
reviews what is uploaded and ticks an explicit consent first.

**What is stored**
- **Object** — the original gzip of the capture bundle (`schema: 1` JSON) in the **private**
  `diagnostic-captures` bucket at `<user_id>/<capture_id>.json.gz`: device model, firmware, transport;
  app/codec versions; per-step results; the wire log (timestamped hex frames) and job logs.
  Redaction happens **on the user's machine, before upload** (ForgeFX): preset/scene names are blanked,
  preset dump payloads are reduced to their header, and no file paths, host names or account emails are
  included. The server validates shape and size only — it cannot re-check redaction, so it stores what it
  is given.
- **Row** in `diagnostic_captures` — `user_id`, the bundle's own `capture_id`, `model`, `firmware`, version
  stamps (`app`: forgefx/codec/axis), `state`, `bytes`, `object_path`, `created_at`, `expires_at`.

**Who can read it:** nobody through the API — not even the uploader. The table has RLS enabled with **no
policy** (and its privileges are revoked from `anon`/`authenticated`); the bucket is private with **no
storage policy**. Only the **service role** (the maintainer, plus the edge functions) can read or write.

**Upload API** — Edge function `diagnostic-captures` (`verify_jwt = true`; the user is also resolved from
the token). `POST` only; body = gzip of the bundle JSON with `Content-Type: application/gzip` (do **not** set
`Content-Encoding: gzip` — the function must see the original bytes).

| Result | When |
|---|---|
| `200 { captureId }` | stored; `captureId` is the `diagnostic_captures.id`. Re-uploading the same bundle id from the same user is idempotent: `200` with the existing id (+ `deduped: true`) and no second copy |
| `400 { error, message }` | `empty-body`, `invalid-gzip`, `invalid-json`, or `invalid-bundle` (needs `schema === 1`; `id` matching `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`; `device.model` integer 0..255; `device.firmware` string ≤ 64 chars or null; `steps` array of objects) |
| `401 { error: 'unauthorized' }` | missing/invalid/expired token |
| `413 { error: 'too-large', stage, limit }` | > **25 MiB** compressed (checked on `Content-Length` and while streaming, before the body is buffered), or > **64 MiB** once decompressed (gzip-bomb guard; sized for the 256 MB edge-worker memory) |
| `429 { error: 'rate-limited', … }` + `Retry-After` | already **5** new captures in the last rolling hour |
| `500 { error: 'internal' }` | storage/database failure (details only in the function log) |

**Retention:** `expires_at` defaults to `created_at + 180 days`. The `gc-blobs` function removes expired rows
together with their objects, and also objects that no row references any more (a crashed upload, or leftovers
after account deletion) once they are older than 24 h; its JSON result reports this under `diagnostics`.
**Schedule it** — `gc-blobs` is not self-scheduling; run it **once a day**. With `pg_cron` + `pg_net`
(Dashboard → Database → Extensions) and the `GC_SECRET` kept in Vault, run once in the SQL editor
(placeholders only — never commit real values):

```sql
select vault.create_secret('<GC_SECRET>', 'gc_secret');
select cron.schedule('gc-blobs-daily', '17 3 * * *', $$
  select net.http_post(
    url := 'https://<project-ref>.supabase.co/functions/v1/gc-blobs',
    headers := jsonb_build_object('x-gc-secret',
      (select decrypted_secret from vault.decrypted_secrets where name = 'gc_secret'))
  );
$$);
```

Preview what would be removed first with `POST …/functions/v1/gc-blobs?dry=1` (same header).

**Deletion:** the `delete-account` function removes the user's capture objects and rows (the auth-user delete
also cascades the rows). There is no self-service per-capture delete (users cannot read their captures);
deleting a single capture on request is a service-role operation (below).

**Reading captures (maintainer, service role).** Keep the key in your environment or secret store — never in
the repo:

```bash
export SUPABASE_URL=https://<project-ref>.supabase.co
export SERVICE_ROLE_KEY=...   # Dashboard → Settings → API; server-side only

# list, newest first (filter e.g. &model=eq.17&firmware=eq.12.0)
curl -s "$SUPABASE_URL/rest/v1/diagnostic_captures?select=id,user_id,capture_id,model,firmware,state,bytes,created_at,expires_at&order=created_at.desc&limit=50" \
  -H "apikey: $SERVICE_ROLE_KEY" -H "Authorization: Bearer $SERVICE_ROLE_KEY"

# download one (path = object_path of the row)
curl -s -o capture.json.gz "$SUPABASE_URL/storage/v1/object/authenticated/diagnostic-captures/<user_id>/<capture_id>.json.gz" \
  -H "Authorization: Bearer $SERVICE_ROLE_KEY"
gunzip -k capture.json.gz

# delete one on request: remove the object, then the row
curl -s -X DELETE "$SUPABASE_URL/storage/v1/object/diagnostic-captures/<user_id>/<capture_id>.json.gz" \
  -H "Authorization: Bearer $SERVICE_ROLE_KEY"
curl -s -X DELETE "$SUPABASE_URL/rest/v1/diagnostic_captures?id=eq.<row-id>" \
  -H "apikey: $SERVICE_ROLE_KEY" -H "Authorization: Bearer $SERVICE_ROLE_KEY"
```

**Tests:** `deno test supabase/functions/diagnostic-captures/` (in-memory fakes; no Supabase stack needed).

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
- [x] Opt-in diagnostic capture upload (`diagnostic_captures` + private bucket + `diagnostic-captures` edge fn)
- [ ] Patreon account link → `subscriptions` (hosted supporter tier)

## License
Copyright © 2026 sKuhLight. Licensed under the **PolyForm Noncommercial License 1.0.0** — see
[`LICENSE.md`](./LICENSE.md). In short: you may use, modify, and self-host this for **any noncommercial
purpose** (personal use, research, non-profits), but **not for commercial advantage or monetary
compensation**. Commercial rights — including the hosted supporter service — are reserved by the author.

> This is *source-available*, not OSI "open source" (an OSI license would have to permit commercial use).
> "Noncommercial" can be a gray area for edge cases — if you want to use Axis Cloud commercially, ask.
