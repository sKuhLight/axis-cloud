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
    20261121140000_diagnostic_reserve_pending_charge.sql  # reserve: pending charged at the cap, refresh/recreate of pending rows
    20261121150000_explicit_grants.sql  # explicit Data API privileges (projects created with the secure defaults)
    20261122120000_subscriptions_source_catchup.sql  # adds subscriptions.source where an older project lacks it (no-op elsewhere)
    20261123120000_editor_cache_uploads.sql  # editor-cache contributions: uploads, coverage, network counters, bucket, reserve/complete
    20261123130000_anonymous_session_hardening.sql  # keeps account-only features closed to anonymous sessions
  functions/                  # Deno edge functions: delete-account, gc-blobs, device-profiles, diagnostic-captures, editor-caches
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
**directly from the client to storage** via a signed upload URL (the function never receives or parses it, so
nothing here depends on a hosted edge function accepting a body of that size). All requests carry
`Authorization: Bearer <user access token>`. `verify_jwt` is **off** for this function on purpose: the handler
authenticates the caller itself before reading anything, so every authentication failure has the same body,
`{ "error": "unauthorized" }` (with the platform check on, a bad token would get the platform's own differently
shaped 401), and verification does not depend on the project's JWT-signing mode. A token that is not
JWT-shaped is refused the same way without a round trip to the Auth server. Anonymous sessions are refused
(`403 account-required`).

1. **Reserve** — `POST /functions/v1/diagnostic-captures` with
   `{ captureId, model, firmware, app?, state?, bytes }`: `captureId` is the bundle's own id
   (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`), `model` an integer 0..255, `firmware` a string (≤ 64) or `null`,
   `app` `{ forgefx, codec, axis? }` (short strings), `state` `done|failed|cancelled`, `bytes` the **exact size of
   the gzip you will upload** (1 … 26214400). The function authenticates, validates, then **reserves a row
   atomically in the database** (one per-user advisory lock around dedup + limits + insert: parallel requests
   cannot race past the limits) and returns
   `200 { captureId, status: 'pending', uploadUrl, token, path, bucket, expiresIn }`. Its `captureId` is the
   **row id** (a UUID) — keep it for finalize. A repeat of a known bundle id is deduped (`deduped: true`, no new
   slot): `status: 'complete'` means nothing is left to do; `status: 'pending'` with a new upload URL means
   upload again; `status: 'pending'` **without** `uploadUrl` means the object is already there — go straight to
   finalize. While no object has been uploaded yet, a repeat also **refreshes the announced `bytes`** (quota
   re-checked), so a retry with a re-gzipped bundle of a different size can still finalize. A pending
   reservation older than ~20 h is **recreated** instead (new row id, new `created_at`; rate limit and quota
   apply as for any new reservation), so you are never handed an upload URL for a row the 24 h sweep is about
   to delete — always use the `captureId` of the latest reserve response.
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
   anywhere server-side. An object that fails these checks (too large, larger than announced, not gzip) is
   **deleted immediately**; the row stays pending, so the client can reserve again (same `captureId` of the
   bundle), upload a corrected file and finalize.

| Status | Body `error` | When |
|---|---|---|
| 400 | `invalid-request`, `invalid-json`, `empty-body`, `invalid-gzip` | malformed request / the stored object is not gzip (finalize) |
| 401 | `unauthorized` | missing, invalid or expired token |
| 403 | `account-required` | anonymous session |
| 404 | `not-found` | finalize: no such row for this user (or it was swept) |
| 409 | `not-uploaded`, `size-mismatch` | finalize: no object yet / object larger than announced (the object is deleted) |
| 413 | `too-large` | `bytes` above 25 MiB, a request body above 8 KiB, or a stored object above 25 MiB |
| 429 | `rate-limited`, `quota-exceeded` | **5** new captures per user per rolling hour (pending reservations count), or more than **200 MiB** in a rolling 30 days. Until finalize confirms the upload, a reservation counts at the full **25 MiB** cap rather than at the announced `bytes` (an unverified claim), so at most 8 unconfirmed reservations can be outstanding; finalize then records the real size and frees the difference. Body has `retryAfterSeconds`; the `Retry-After` header is set and CORS-exposed |
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

## Editor-cache uploads (opt-in contributions, maintainer-only)
When Axis meets a device firmware it has no definitions for, the user can contribute the **definitions cache file
the official Fractal editor saved on their computer** for that device (`effectDefinitions_<model>_<major>p<minor>.cache`)
so the maintainer can prepare a definitions update without an app release. It is never sent automatically: the
user reviews what is sent and ticks an explicit consent first. Only gen-3 devices contribute (Axe-Fx III `0x10`,
FM3 `0x11`, FM9 `0x12`), and only while a firmware is still wanted.

**Who can upload:** a signed-in account **or a Supabase anonymous session** (a per-install anonymous auth user
created by Supabase Auth — no e-mail, no CAPTCHA; its id is unrelated to any telemetry id). Both can list and
delete their own uploads. Anonymous sign-ins must be enabled on the project, which is a **project-wide** switch:
see "Anonymous sessions" below.

> **Deploy gate (all before a client build that uploads ships):**
> 1. Apply the migrations (`supabase db push`), **then** enable anonymous sign-ins (Dashboard → Authentication →
>    Sign In / Providers) — never the other way round.
> 2. Set the function secret `EDITOR_CACHE_IP_SALT` to a random value of **at least 32 characters** (e.g. 64 hex
>    digits: `supabase secrets set EDITOR_CACHE_IP_SALT=<random>`; never commit it). Missing or shorter, the function
>    fails closed: `wanted: false`, uploads `503 paused`.
> 3. Deploy `editor-caches`, `gc-blobs`, `delete-account` and `device-profiles`.
> 4. The daily `gc-blobs` schedule must exist (see "Diagnostic captures") — it enforces the retention below and
>    deletes idle anonymous users.
> 5. **Pin the client-address header** on staging first (see "Limits": the first reservation per worker logs which
>    address headers arrived — names only), then set `EDITOR_CACHE_IP_HEADERS` to that one header in production.
> 6. Mark the firmwares the maintainer already has as covered (SQL under "Coverage"), so nobody is asked for them.

**What is stored**
- **Object** — the uploaded file, **redacted on the user's machine before upload**: every byte of the user's own
  names (preset names, user cab names) is replaced with `_`, lengths unchanged; everything else is the editor's
  firmware definitions. Private `editor-caches` bucket at `<user_id>/<sha256>.cache` (4 MiB cap,
  `application/octet-stream`, no storage policy).
- **Row** in `editor_cache_uploads` — `user_id` (the auth user id, anonymous or account), `model`,
  `device_firmware` (as the device reports it), `file_version` (from the file name), `content_version` (the
  file's own header version, **read by the server** at finalize), generated `version_match`, `file_name`,
  `sha256`, `bytes`, `redaction` counts (`{ version, tables, names }`), sanitized client validation numbers
  (`summary`), version stamps (`app`, version-like strings only), `consent_at` + `consent_version`, `status`,
  `created_at`, `expires_at`. **No IP address, no e-mail, no file path, no host name, no telemetry id.**
- **Network counters** in `editor_cache_ip_usage` — an HMAC-SHA256 of the client's network (IPv4 address or IPv6
  /64) under `EDITOR_CACHE_IP_SALT`, never the address itself; no user id. Used for the per-network limits and so
  that coverage counts one network only once. Kept while the upload it belongs to exists (≤ 180 days); once the
  upload is gone it is unlinked and deleted when it is older than 30 days (the longest limit window).
- **Coverage** in `editor_cache_coverage` — per `(model, firmware)`: `collecting | covered | closed` and a
  contributor count. No user data.

**Who can read it:** only the **service role** (maintainer, edge functions). All three tables have RLS on with no
policy and their privileges revoked from `anon`/`authenticated`. Uploaders see their own uploads only through the
function's listing (no file content).

**Server-side check before an upload is accepted** (finalize; anything else is `422 invalid-cache`, and the stored
object is deleted at once): the stored bytes must hash to the announced `sha256`; be at most 4 MiB; and be a
complete editor definitions cache as observed in the gen-3 editors' files — a 46-byte header whose version
(`u32` major/minor) equals the version in the file name and whose section count equals the sections that
follow; every section and record walks cleanly to the end of the file (the record grammar of the public
[forgefx-midi](https://github.com/sKuhLight/forgefx-midi) cache walker, strict mode); and every name in the
user-name tables (preset names, user/scratchpad cab banks, unknown special tables) is empty or all `_`. On top, a
**plausibility floor** — at least 32 KiB, 16 sections, 500 records and a preset-name table (real caches of the
contributing devices: 278–329 KB, 45–57 sections, ~2,500–2,900 records) — so tiny hand-made files that walk
cleanly cannot be used to cover a firmware. The file name must also be the editor's own name and agree with the
claimed model and file version (`400` at reserve). Rules and reasons: `supabase/functions/editor-caches/validate.ts`.

**Flow** — the function `editor-caches` handles small JSON requests only; the file goes straight from the client
to storage via a signed upload URL. Authenticated calls carry `Authorization: Bearer <access token>` (account or
anonymous session); `verify_jwt` is off because the status call is public and the handler verifies tokens itself.

0. **Status (public)** — `GET /functions/v1/editor-caches?model=17&firmware=13.0` →
   `200 { model, firmware, wanted }` (`Cache-Control: public, max-age=600`). `wanted` is false when uploads are
   paused, the model cannot contribute, or the firmware is covered/closed. Nothing else is revealed.
1. **Reserve** — `POST /functions/v1/editor-caches` with
   `{ model, deviceFirmware, fileVersion, contentVersion?, fileName, sha256, bytes, redaction: { version, tables, names }, summary?, app?, consentAt, consentVersion }`
   (`sha256` of the bytes to upload, `bytes` their exact size, `consentAt` ISO within ±24 h of server time,
   `consentVersion` ≥ 2 — the first disclosure text that covers uploads without an account; `app` stamps must look
   like versions, e.g. `0.9.0-beta`). Answers `200 { uploadId, status: 'pending', uploadUrl, token, path, bucket, expiresIn }`;
   `{ uploadId, status: 'complete', deduped: true }` (you sent this file already); `{ uploadId: null, status: 'complete', deduped: true }`
   (someone else sent the identical file — nothing is stored); `{ uploadId, status: 'pending', deduped: true }` without
   `uploadUrl` (the object is already there — finalize). Pending reservations refresh/recreate exactly like
   diagnostic captures (new row after ~20 h).
2. **Upload** — `supabase.storage.from('editor-caches').uploadToSignedUrl(path, token, bytes, { contentType: 'application/octet-stream' })`
   (or `PUT uploadUrl`; on a local stack the URL may point at the internal host — use `path` + `token`).
3. **Finalize** — `POST /functions/v1/editor-caches/finalize` with `{ uploadId }` → `200 { uploadId, status: 'complete', covered }`
   (`covered`: the firmware is no longer collecting). Runs the server-side check above.
4. **Delete (self-service)** — `POST /functions/v1/editor-caches/delete` with `{ uploadId }` → `200 { uploadId, deleted: true }`
   (own uploads only, else `404`; object first, then the row; works while paused).
5. **My uploads** — `GET /functions/v1/editor-caches/mine` → `200 { uploads: [{ uploadId, model, deviceFirmware, fileVersion, contentVersion, versionMatch, fileName, sha256, bytes, status, createdAt, expiresAt }] }`.

| Status | Body `error` | When |
|---|---|---|
| 400 | `invalid-request`, `invalid-json`, `empty-body`, `consent-required` | malformed request; renamed/foreign file name; consent fields missing, out of range, or for a disclosure text older than version 2 |
| 401 | `unauthorized` | missing, invalid or expired token |
| 403 | `account-required` | reserve/finalize by an anonymous session while `EDITOR_CACHE_ALLOW_ANONYMOUS=0` (listing and deleting stay open) |
| 404 | `not-found` | no such upload for this uploader |
| 409 | `not-uploaded`, `size-mismatch`, `hash-mismatch`, `not-wanted`, `firmware-limit` | finalize before upload / object larger than announced / bytes do not match `sha256` (object deleted) / firmware covered or closed, or a model that cannot contribute / 2 uploads for this firmware already |
| 413 | `too-large` | `bytes` above 4 MiB, a request body above 8 KiB, or a stored object above 4 MiB |
| 422 | `invalid-cache` (+ `reason`: `size`, `implausible`, `header-version`, `version-mismatch`, `section-count`, `structure`, `too-complex`, `not-redacted`) | the stored file failed the server-side check (object deleted) |
| 429 | `rate-limited`, `quota-exceeded` (+ `scope`: `uploader` or `ip`) | see limits; `retryAfterSeconds` in the body, `Retry-After` header (CORS-exposed) |
| 503 | `paused` | `EDITOR_CACHE_UPLOADS=off`, or `EDITOR_CACHE_IP_SALT` missing / shorter than 32 characters |
| 500 | `internal` | storage/database failure (details only in the function log) |

**Limits** (constants in `validate.ts`, enforced atomically in `reserve_editor_cache_upload`):

| Limit | Value |
|---|---|
| File size | 4 MiB (bucket enforces it too) |
| Rate | 5 new uploads per hour — per uploader **and** per client network |
| Volume | 20 MiB per 30 days — per uploader **and** per client network; an unconfirmed reservation counts at the full 4 MiB until finalize records the real size |
| Per firmware | 2 uploads per (uploader, model, firmware) |
| Coverage | covered after **2 distinct uploaders on 2 distinct networks** with a complete, version-matched upload |
| Signed upload URL | 2 h; pending refresh max age 20 h; gc grace 24 h |

Anonymous uploader ids cost nothing to mint, so the **per-network** limits are the ones that bind an abuser; their
counters outlive deleted uploads, so deleting and re-uploading does not reset them. By default the client network is
read from `cf-connecting-ip`, then `x-real-ip`, then the **last** `x-forwarded-for` entry (earlier entries are
client-supplied). Which of these the hosted platform actually sets, and whether a client can forge it, is **not
verified yet**: the first reservation each worker serves logs which address headers were present and how many
`x-forwarded-for` entries there were (header names and a count — never values), and a request without any usable
address logs a warning and is limited in one shared bucket. Check that log on staging (requests from two different
networks must produce two different counters; a forged `x-forwarded-for` must change nothing), then **pin**
`EDITOR_CACHE_IP_HEADERS` to the one header the platform's proxy sets. A self-hosted deployment does the same for
its own proxy.

**Coverage ("stop asking").** A firmware becomes `covered` automatically once 2 distinct uploaders (anonymous ids
count) on 2 distinct networks have a complete upload whose file version (name or header) equals the device
firmware — `contributors` = distinct uploaders, counted at most once per network key, so one network cannot cover
a firmware alone. Uploads of an older/other file are stored but never count. The maintainer manages coverage with
a service-role-only function (SQL editor; the firmware is normalized, `'32.06'` → `'32.6'`):

```sql
select public.set_editor_cache_coverage(17, '13.0', 'covered');     -- stop asking (FM3 = 17 = 0x11, firmware 13.0)
select public.set_editor_cache_coverage(17, '14.0', 'closed');      -- never collect (e.g. a beta)
select public.set_editor_cache_coverage(17, '13.0', 'collecting');  -- reopen: count restarts; only uploads from now on count
select model, device_firmware, state, contributors, updated_at from public.editor_cache_coverage order by 1, 2;
```

Nothing is pre-marked by the migrations (a local `db reset` starts with every firmware wanted, which the manual
acceptance run relies on); on the hosted project the maintainer runs one `covered` line per firmware he already
has, after `db push` and before the client ships. Global stop: `supabase secrets set EDITOR_CACHE_UPLOADS=off`.

**Retention and deletion.** `expires_at` = `created_at + 180 days`; `gc-blobs` removes expired uploads with their
objects, reservations still pending after 24 h, unreferenced objects older than 24 h (reported under
`editorCaches`), network counters no upload references any more once they are older than 30 days
(`editorCacheNetworkCounters`), and anonymous auth users without uploads (see "Anonymous sessions";
`anonymousUsers`). An uploader deletes a single upload with `POST …/editor-caches/delete`; `delete-account` (also
callable with an anonymous session) removes all objects and rows of the caller and the auth user — leftovers are
swept by `gc-blobs` like diagnostic captures. Coverage is a high-water mark and is not lowered by deletions (it
holds no user data).

**Reading uploads (maintainer, service role):**

```bash
# list complete uploads, newest first (filter e.g. &model=eq.17&device_firmware=eq.13.0&version_match=is.true)
curl -s "$SUPABASE_URL/rest/v1/editor_cache_uploads?select=id,model,device_firmware,file_version,content_version,version_match,file_name,sha256,bytes,redaction,summary,created_at,expires_at&status=eq.complete&order=created_at.desc&limit=50" \
  -H "apikey: $SERVICE_ROLE_KEY" -H "Authorization: Bearer $SERVICE_ROLE_KEY"

# download one (path = <user_id>/<sha256>.cache, the row's object_path)
curl -s -o upload.cache "$SUPABASE_URL/storage/v1/object/authenticated/editor-caches/<user_id>/<sha256>.cache" \
  -H "Authorization: Bearer $SERVICE_ROLE_KEY"

# delete one on request: the object, then the row
curl -s -X DELETE "$SUPABASE_URL/storage/v1/object/editor-caches/<user_id>/<sha256>.cache" -H "Authorization: Bearer $SERVICE_ROLE_KEY"
curl -s -X DELETE "$SUPABASE_URL/rest/v1/editor_cache_uploads?id=eq.<row-id>" \
  -H "apikey: $SERVICE_ROLE_KEY" -H "Authorization: Bearer $SERVICE_ROLE_KEY"
```

Keep downloaded copies without the `user_id` (model + firmware are enough); a redacted file is device data.

**Function secrets:** `editor-caches`: `EDITOR_CACHE_IP_SALT` (required, ≥ 32 characters; rotating it resets the
per-network counters), `EDITOR_CACHE_UPLOADS=off` (kill switch), `EDITOR_CACHE_ALLOW_ANONYMOUS=0` (no new
anonymous uploads; listing and deleting stay open), `EDITOR_CACHE_IP_HEADERS` (client-address headers, see above).
`gc-blobs`: `ANONYMOUS_USER_IDLE_DAYS` (default 30, `off` disables the anonymous-user cleanup).

**Tests:** `deno test supabase/functions/editor-caches/` (validator against synthetic caches, request parsing,
network key, handler flow against in-memory fakes; no stack needed) and, on a local stack,
`npx --yes supabase@latest test db` (`editor_cache_uploads.test.sql`, `anonymous_sessions.test.sql`).

### Anonymous sessions (project-wide)
Enabling anonymous sign-ins gives every caller who asks a valid `authenticated` JWT (with `is_anonymous: true`),
rate-limited by Supabase Auth per IP (`[auth.rate_limit] anonymous_users`, 30/h). Everything written for
"signed-in users" would otherwise admit them, so the account-only features refuse anonymous sessions explicitly:
- cloud sync tables `documents`, `preset_versions`, `backups`, the `preset-blobs` bucket and the Remote relay
  channel — restrictive RLS policies (`…_anonymous_session_hardening.sql`);
- `device-profiles` publishing (`403 account-required`) and `diagnostic-captures` (already refused).
`delete-account` accepts anonymous sessions on purpose (self-erasure).

**What Supabase Auth itself stores for an anonymous user, and how long.** Like for any user, Auth (GoTrue) keeps
a row in `auth.users` (`is_anonymous = true`), its sessions in `auth.sessions` — **including the client's IP
address and user agent** — and entries in its audit log `auth.audit_log_entries` (which also record an IP
address). These live outside this project's schema. To bound them:
- **Anonymous users are deleted** by `gc-blobs` (Auth admin API) once they own nothing in the upload stores and
  have not signed in for `ANONYMOUS_USER_IDLE_DAYS` (default **30**; `off` disables). That removes the user row and
  its sessions with it. Accounts — including anonymous users who later linked an e-mail — are never touched. A
  deleted anonymous install simply signs in anonymously again (new id) the next time it needs one.
- **The audit log is not removed by deleting a user**, and nothing in this repo purges it: its entries (with IP
  address) stay until the project's audit-log settings or the maintainer remove them. Either turn off storing the
  Auth audit log in the database where the hosted project offers that option, or schedule a purge in the SQL
  editor (placeholder interval; review it before use — the `auth` schema is managed by Supabase, and if the
  `postgres` role may not delete there, use the dashboard option instead):
  `select cron.schedule('auth-audit-purge', '41 3 * * *', $$delete from auth.audit_log_entries where created_at < now() - interval '30 days'$$);`
- The platform's request logs (API gateway, edge functions) are kept on Supabase's side for the plan's log retention.
The privacy text must name all three: Auth session/audit records (IP address, user agent), their retention
(anonymous users ≤ 30 days idle after their last upload is gone; audit log as configured), and the platform logs.

## Gating (so it never ships dark)
The entire sync layer is behind `AXIS_CLOUD=1`. With it unset, ForgeFX loads no cloud code and Axis
shows no login. **Release builds do set it**: the Axis release workflow writes `AXIS_CLOUD=1` and the project's
Supabase URL + anon key into the bundled ForgeFX configuration, so every cloud feature (including diagnostic
captures and editor-cache uploads) reaches released users once its client code ships.

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
- [x] Opt-in editor-cache contributions (`editor_cache_*` + private bucket + `editor-caches` edge fn; accounts and anonymous sessions)
- [ ] Schedule `gc-blobs` daily (deploy gate for both uploads — see "Diagnostic captures")
- [ ] Hosted project: `EDITOR_CACHE_IP_SALT` secret (≥ 32 chars), anonymous sign-ins on (after the migrations), client-address header pinned after a staging check, covered firmwares marked, Auth audit-log retention decided
- [ ] Patreon account link → `subscriptions` (hosted supporter tier)

## License
Copyright © 2026 sKuhLight. Licensed under the **PolyForm Noncommercial License 1.0.0** — see
[`LICENSE.md`](./LICENSE.md). In short: you may use, modify, and self-host this for **any noncommercial
purpose** (personal use, research, non-profits), but **not for commercial advantage or monetary
compensation**. Commercial rights — including the hosted supporter service — are reserved by the author.

> This is *source-available*, not OSI "open source" (an OSI license would have to permit commercial use).
> "Noncommercial" can be a gray area for edge cases — if you want to use Axis Cloud commercially, ask.
