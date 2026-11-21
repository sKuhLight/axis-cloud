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
    20261121130000_diagnostic_captures_signed_upload.sql  # status, atomic reserve function (limits, quota), bucket re-assert
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

> **Deploy gate:** retention (below) only happens when `gc-blobs` runs on a schedule, and the schedule is **not**
> part of the migrations. Create it (and confirm one `?dry=1` run reports sensible numbers) **before** enabling
> the upload in a released build — otherwise captures, pending reservations and orphans accumulate forever.

**What is stored**
- **Object** — the original gzip of the capture bundle (`schema: 1` JSON) in the **private**
  `diagnostic-captures` bucket at `<user_id>/<capture_id>.json.gz`: device model, firmware, transport;
  app/codec versions; per-step results; the wire log (timestamped hex frames) and job logs.
  Redaction happens **on the user's machine, before upload** (ForgeFX): preset/scene names are blanked,
  preset dump payloads are reduced to their header, and no file paths, host names or account emails are
  included. The server never opens the bundle — it checks size and the gzip magic bytes only — so it cannot
  re-check redaction and stores what it is given.
- **Row** in `diagnostic_captures` — `user_id`, the bundle's own `capture_id`, `model`, `firmware`, version
  stamps (`app`: forgefx/codec/axis), `state`, `bytes`, `object_path`, `status` (`pending` → `complete`),
  `created_at`, `expires_at`.

**Who can read it:** nobody through the API — not even the uploader. The table has RLS enabled with **no
policy** (and its privileges are revoked from `anon`/`authenticated`); the bucket is private with **no
storage policy**. Only the **service role** (the maintainer, plus the edge functions) can read or write.

**Upload flow** — the edge function `diagnostic-captures` only handles small JSON requests; the bundle goes
**directly from the client to storage** via a signed upload URL (the function never receives or parses it, and
hosted edge functions could not take a 25 MiB body anyway). All requests carry `Authorization: Bearer <user
access token>`. `verify_jwt` is **off** for this function on purpose: the handler authenticates the caller itself
before reading anything, so every authentication failure has the same body, `{ "error": "unauthorized" }` (with
the platform check on, a bad token would get the platform's own differently shaped 401), and verification does
not depend on the project's JWT-signing mode. Anonymous sessions are refused (`403 account-required`).

1. **Reserve** — `POST /functions/v1/diagnostic-captures` with
   `{ captureId, model, firmware, app?, state?, bytes }`: `captureId` is the bundle's own id
   (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`), `model` an integer 0..255, `firmware` a string (≤ 64) or `null`,
   `app` `{ forgefx, codec, axis? }` (short strings), `state` `done|failed|cancelled`, `bytes` the **exact size of
   the gzip you will upload** (1 … 26214400). The function authenticates, validates, then **reserves a row
   atomically in the database** (one per-user advisory lock around dedup + limits + insert: parallel requests
   cannot race past the limits) and returns
   `200 { captureId, status: 'pending', uploadUrl, token, path, bucket, expiresIn }`. Its `captureId` is the
   **row id** (a UUID) — keep it for finalize. A repeat of a known bundle id is deduped (`deduped: true`, no new
   slot or quota): `status: 'complete'` means nothing is left to do; `status: 'pending'` with a new upload URL
   means upload again; `status: 'pending'` **without** `uploadUrl` means the object is already there — go
   straight to finalize.
2. **Upload** — send the gzip to storage with the returned credentials, either
   `PUT <uploadUrl>` with `Content-Type: application/gzip` (and the project's `apikey` header, as supabase-js sends
   it), or — preferred, because it builds the URL from your own configured base URL —
   `supabase.storage.from(bucket).uploadToSignedUrl(path, token, body, { contentType: 'application/gzip' })`.
   The URL/token is valid for `expiresIn` seconds (2 h), can only **create** the object (an existing one is
   never overwritten), and the bucket itself enforces **25 MiB** and `application/gzip`. (On a local `supabase start` stack the function sees the
   internal API host, so `uploadUrl` may not be reachable from the host: use `path` + `token`.)
3. **Finalize** — `POST /functions/v1/diagnostic-captures/finalize` (or `?action=finalize`) with
   `{ captureId: <row id from step 1> }`: the function checks that the row is yours and pending, that the object
   exists, that its size is ≤ the announced `bytes` (and ≤ 25 MiB), and — with a 2-byte range read — that it
   starts with the gzip magic bytes; it then sets `status = 'complete'` and the actual size and answers
   `200 { captureId, status: 'complete' }` (idempotent). No full download, decompression or JSON parsing happens
   anywhere server-side.

| Status | Body `error` | When |
|---|---|---|
| 400 | `invalid-request`, `invalid-json`, `empty-body`, `invalid-gzip` | malformed request / the stored object is not gzip (finalize) |
| 401 | `unauthorized` | missing, invalid or expired token |
| 403 | `account-required` | anonymous session |
| 404 | `not-found` | finalize: no such row for this user (or it was swept) |
| 409 | `not-uploaded`, `size-mismatch` | finalize: no object yet / object larger than announced |
| 413 | `too-large` | `bytes` above 25 MiB, a request body above 8 KiB, or a stored object above 25 MiB |
| 429 | `rate-limited`, `quota-exceeded` | **5** new captures per user per rolling hour (pending reservations count), or more than **200 MiB** announced in a rolling 30 days. Body has `retryAfterSeconds`; the `Retry-After` header is set and CORS-exposed |
| 500 | `internal` | storage/database failure (details only in the function log) |

**Retention:** `expires_at` defaults to `created_at + 180 days`. The `gc-blobs` function (see below for the
schedule) removes
- expired rows together with their objects (objects first, then rows);
- reservations still `pending` after 24 h (the upload was never confirmed) — rows first and only if still
  pending, so an object of a capture finalized in the meantime is never deleted — and then their objects;
- objects that no row references any more (a crashed reservation, or leftovers after account deletion) once
  they are older than 24 h.

Its JSON result reports all of this under `diagnostics`; `POST …/gc-blobs?dry=1` (same header) previews it.

**Schedule `gc-blobs` once a day** (not self-scheduling; see the deploy gate above). With `pg_cron` + `pg_net`
(Dashboard → Database → Extensions) and the `GC_SECRET` kept in Vault, run once in the SQL editor
(placeholders only — never commit real values):

```sql
select vault.create_secret('<GC_SECRET>', 'gc_secret');
select cron.schedule('gc-blobs-daily', '17 3 * * *', $$
  select net.http_post(
    url := 'https://<project-ref>.supabase.co/functions/v1/gc-blobs',
    headers := jsonb_build_object('x-gc-secret',
      (select decrypted_secret from vault.decrypted_secrets where name = 'gc_secret')),
    timeout_milliseconds := 120000  -- pg_net's default is 5000 ms; a sweep can take longer
  );
$$);
```

**Deletion:** the `delete-account` function removes the user's capture objects and rows (deleting the auth
user also cascades the rows). The object removal is **best-effort and logged**: if it fails, the account
deletion still completes and the leftover objects — now unreferenced — are removed by the next scheduled
`gc-blobs` run once they are older than 24 h, i.e. within roughly a day or two. (An upload URL a user obtained
shortly before deleting their account can leave one such object too; the same sweep removes it.) There is no
self-service per-capture delete (users cannot read their captures); deleting a single capture on request is a
service-role operation (below).

**Reading captures (maintainer, service role).** Keep the key in your environment or secret store — never in
the repo:

```bash
export SUPABASE_URL=https://<project-ref>.supabase.co
export SERVICE_ROLE_KEY=...   # Dashboard → Settings → API; server-side only

# list completed captures, newest first (filter e.g. &model=eq.17&firmware=eq.12.0)
curl -s "$SUPABASE_URL/rest/v1/diagnostic_captures?select=id,user_id,capture_id,model,firmware,state,bytes,created_at,expires_at&status=eq.complete&order=created_at.desc&limit=50" \
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

**Tests:** `deno test supabase/functions/diagnostic-captures/` (handler logic against in-memory fakes; no
Supabase stack needed) and, on a local stack, `npx --yes supabase@latest test db` (pgTAP: the reservation
function, limits, grants, constraints, deny-by-default access).

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
- [x] Opt-in diagnostic capture upload (`diagnostic_captures` + private bucket + `diagnostic-captures` edge fn, signed-upload flow)
- [ ] Schedule `gc-blobs` daily (deploy gate for the diagnostic upload — see "Diagnostic captures")
- [ ] Patreon account link → `subscriptions` (hosted supporter tier)

## License
Copyright © 2026 sKuhLight. Licensed under the **PolyForm Noncommercial License 1.0.0** — see
[`LICENSE.md`](./LICENSE.md). In short: you may use, modify, and self-host this for **any noncommercial
purpose** (personal use, research, non-profits), but **not for commercial advantage or monetary
compensation**. Commercial rights — including the hosted supporter service — are reserved by the author.

> This is *source-available*, not OSI "open source" (an OSI license would have to permit commercial use).
> "Noncommercial" can be a gray area for edge cases — if you want to use Axis Cloud commercially, ask.
