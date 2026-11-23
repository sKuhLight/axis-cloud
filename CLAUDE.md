# axis-cloud — Claude Code Context

Optional **cloud-sync backend** for the [Axis](https://github.com/sKuhLight/Axis)
editor: config + preset backup with version history, per-user isolation, and a shared
device-definition profile store. It is a **Supabase project** (Postgres + Auth +
Storage) — no custom server. Source-available, self-hostable, noncommercial
(PolyForm-NC 1.0.0). `README.md` is the product-level design; this file is the working
guide for making changes.

## Architecture / Layout

```
supabase/
  config.toml               # CLI config: auth URLs, storage limit, per-function verify_jwt (NO secrets)
  migrations/               # versioned schema, applied in filename order — IMMUTABLE once applied
  functions/                # Deno edge functions (server-side, service-role)
.env.example                # SUPABASE_URL / SUPABASE_ANON_KEY / AXIS_CLOUD (copy to .env; never commit .env)
```

**Migrations** (`supabase/migrations/`, timestamp-prefixed, run in order):
- `…_init.sql` — core tables `documents`, `preset_versions`, `backups`,
  `subscriptions`; the private `preset-blobs` Storage bucket. RLS scopes every row to
  `auth.uid()`.
- `…_debug_reports_bucket.sql` — anonymous insert-only `debug-reports` bucket (no
  SELECT/UPDATE/DELETE policy → push-only, 5 MiB cap).
- `…_realtime_remote_channel_authz.sql` — Realtime authz: a user may send/receive only
  on `remote:<their-uid>`.
- `…_free_tier_preset_quota.sql` — `tier_limits` (data), `is_paid()`,
  `enforce_preset_quota()` trigger, `preset_quota()` readout; caps free-tier
  storage/snapshots/backups as a server-side backstop.
- `…_harden_quota_functions.sql` — revokes EXECUTE on the quota/paid functions from
  public/anon (advisor hardening) — deliberate; do not loosen.
- `…_device_profiles.sql` — shared, public-read `device_profiles` (NOT user data);
  writes are service-role-only (no client write policy).
- `…_diagnostic_captures.sql`, `…_diagnostic_captures_signed_upload.sql`,
  `…_diagnostic_reserve_pending_charge.sql` — maintainer-only `diagnostic_captures` (RLS on, no
  policy, privileges revoked) + private `diagnostic-captures` bucket; `reserve_diagnostic_capture()`
  (security definer, service_role only: dedup, rate limit, byte quota with pending charged at the cap,
  refresh/recreate of pending rows; SQLSTATEs `XQ001`/`XQ002`).
- `…_explicit_grants.sql` — explicit Data API privileges for projects created with the secure
  defaults (no implicit grants); `device_profiles.created_by` withheld from clients.
- `…_subscriptions_source_catchup.sql` — adds `subscriptions.source` where an older project lacks it.
- `…_editor_cache_uploads.sql` — editor-cache contributions: `editor_cache_uploads` (no IP, no
  e-mail), `editor_cache_coverage` (contributors = distinct uploaders, once per network key),
  `editor_cache_ip_usage` (HMAC'd network keys; kept while their upload exists, unlinked ones pruned at
  30 d), all deny-by-default; private `editor-caches` bucket; `reserve_editor_cache_upload()`
  (`XQ001`–`XQ006`), `complete_editor_cache_upload()`, `set_editor_cache_coverage()` — service_role only.
- `…_anonymous_session_hardening.sql` — restrictive policies keeping cloud sync, `preset-blobs` and the
  Remote channel closed to Supabase anonymous sessions (anonymous sign-ins are on for editor caches).
- `…_definition_sources.sql` — shared device definitions (cloud v2): PUBLIC `definition_sources` (sanitized raw
  source per (model, firmware, kind, fact hash); column-level grant + RLS hiding rejected/quarantined/orphaned rows;
  day-only dates for clients), PRIVATE `definition_source_contributions` (user id + keyed network marker, one vote per
  uploader and kind, unlinked after 180 d), `definition_source_reports` (spot checks, 180 d),
  `definition_source_network_usage` (per-network counters, no user id, 30 d); service_role-only functions
  `contribute_…` / `withdraw_…` / `report_…` / `select_definition_sources` / `cleanup_orphan_…` /
  `unlink_expired_…` (`XQ001`/`XQ002` uploader, `XQ005`/`XQ006` network, `XQ007` rejected facts).
- `…_definition_sources_orphan_reset.sql` — `contribute_definition_source` deletes an unpinned source without
  contributions (under the source-key lock) before sharing identical facts, so an orphan is never revived.
- `…_device_profiles_ranking.sql` — v1 `device_profiles` ranking key: `row_count` = (family, parameter id) entries of
  `profile->'ranges'`, a STORED GENERATED column (database-computed, backfills existing rows, nobody can set it) via
  `device_profile_row_count(jsonb)` (immutable, EXECUTE for service_role only: a generated column's function runs with
  the inserting role's privileges); index `(model, firmware, source, row_count desc nulls last, created_at)`; column
  granted to anon/authenticated for SELECT only.

**Edge functions** (`supabase/functions/*/index.ts`, Deno + `supabase-js`):
- `delete-account` — GDPR erase. `verify_jwt = true`; identifies the caller from their
  token, then removes their blobs + rows + auth user with the service role.
- `gc-blobs` — orphan-blob sweep. `verify_jwt = false`, gated by the `GC_SECRET` header;
  deletes `preset-blobs` objects not referenced by any `preset_versions.blob_path`,
  skipping objects <24 h old. `?dry=1` reports without deleting.
- `device-profiles` — shared profile store (v1). `verify_jwt = false` (GET is public); POST
  verifies the JWT manually (anonymous sessions refused), validates + size-caps the body, computes
  the content hash server-side, rate-limits, and inserts with the service role. Logic in `handler.ts` behind a
  `Deps` seam (`handler.test.ts`). GET serves the BEST row, never the newest: `source` editor-cache first, then
  `row_count` desc, then `created_at` asc (`PROFILE_ORDER`; the response shape is the v1 one). Deploy the ranking
  migration BEFORE the function (GET orders by `row_count`).
- `diagnostic-captures` — opt-in diagnostic upload, signed-upload flow (reserve → client uploads
  to storage → finalize checks size + gzip magic). `verify_jwt = false`, handler authenticates;
  anonymous sessions refused. Logic in `handler.ts`/`validate.ts` behind a `Deps` seam.
- `editor-caches` — editor definitions-cache contributions, same signed-upload pattern. Public
  `GET ?model&firmware` → `{ wanted }`; reserve / finalize / delete / `GET /mine` for accounts AND
  anonymous sessions. Finalize hashes the stored object and runs a structure + redaction check of the
  cache (`validate.ts`, self-contained mirror of the codec's walker + a plausibility floor) before
  accepting. Per-uploader and per-network limits; secrets `EDITOR_CACHE_IP_SALT` (required, ≥ 32
  chars), `EDITOR_CACHE_UPLOADS=off`, `EDITOR_CACHE_IP_HEADERS` (pin after a staging check).
- `definition-sources` — shared device definitions (cloud v2). Public `GET ?model&firmware&rawFormat` (best row
  per kind + `alternatives`) and `GET /source/<id>` (the handler re-applies the public read filter: service role
  bypasses RLS); contribute / `POST /withdraw` / `GET /mine` / `POST /report` for accounts AND anonymous sessions.
  `validate.ts` re-runs the codec's sharing rules and keeps a sanitized copy (unknown keys dropped, `contentSha256` /
  `walk.abortReason` stripped, `capturedAt` day-coarsened, user tables / tolerant parses refused, plausibility
  floor over distinct positions and record-carrying sections/blocks); `facts.ts` computes the fact hash
  (byte-identical to the codec's `sourceFactHash`, pinned by the golden vectors in `fixtures/` — copied verbatim from
  forgefx-midi, never edited here), summary, quality, coverage score.
  An Auth outage answers `503 auth-unavailable`, never 401.
  Secrets `DEFINITION_SOURCES_IP_SALT` (required for writes, ≥ 32 chars, ≠ `EDITOR_CACHE_IP_SALT`), `DEFINITION_SOURCES`
  (`on|readonly|off`), `DEFINITION_SOURCES_ALLOW_ANONYMOUS`, `DEFINITION_SOURCES_IP_HEADERS`.
- `gc-blobs` also sweeps both private upload stores (`sweepPrivateUploads`), prunes unlinked
  editor-cache network counters, runs the shared-definitions retention (`unlink_expired_definition_contributions`,
  `cleanup_orphan_definition_sources`; block `definitionSources`), and deletes anonymous auth users that own no
  upload and no LINKED definition contribution after `ANONYMOUS_USER_IDLE_DAYS` (default 30) via the Auth admin API;
  ownership is checked with exact row counts (`owners.ts`), because Data API answers are silently capped at max-rows.
- `delete-account` withdraws the caller's definition contributions through the SQL function FIRST (ordered locks,
  orphans deleted at once), deletes their reports, then the auth user, then cleans up orphans.
- `_shared/` — `cors.ts` (Allow-Headers list) and `network.ts` (`clientNetwork`, `networkKey` with a per-store HMAC
  domain, `DEFAULT_IP_HEADERS`); editor-caches re-exports the network functions from its `validate.ts`.

**Storage buckets:** `preset-blobs` (private, per-user path RLS, per-object size cap),
`debug-reports` (private, insert-only), `diagnostic-captures` and `editor-caches` (private, no
storage policy — signed upload URLs from the edge functions only).

**RLS / quota model:** every user table has RLS with `auth.uid() = user_id`, so the anon/
publishable key is safe to expose — RLS protects every row. Quotas are enforced by a
`SECURITY DEFINER` trigger as a backstop (the client pre-flights); paid users
(`subscriptions.active` within period) bypass. `device_profiles` is the one public-read,
service-role-write table (shared derived data, not user data), and `definition_sources` the second (public
column-level read, writes only through the service-role functions). **Anonymous sign-ins are enabled**
(editor caches): an anonymous session is role `authenticated` with `is_anonymous: true`, so any new
account-only policy or function must refuse it explicitly (see the hardening migration).

## Commands (Supabase CLI)

No local CLI, Deno, or Docker is assumed — invoke the CLI through `npx`:

- `npx --yes supabase@latest start` / `stop` — local stack (**needs Docker running**).
- `npx --yes supabase@latest db reset` — rebuild the local DB from `migrations/` + seed.
- `npx --yes supabase@latest functions serve <name>` — run an edge function locally.
- `npx --yes supabase@latest db diff` — diff the local DB vs migrations (to author a new one).
- `npx --yes supabase@latest status` — inspect the running local stack.

**There is no automated test gate (no CI) in this repo yet.** What exists: Deno unit tests
that need no stack — `deno test supabase/functions/` (editor-caches, diagnostic-captures, definition-sources,
device-profiles, _shared; Deno is not assumed installed: `npx --yes deno@2 test supabase/functions/` works) — and pgTAP suites under
`supabase/tests/database/` that need the Docker-gated local stack (`… test db`). Do not claim a
passing gate that does not exist. (Follow-up tracked in Plane.)

Remote-mutating ops (`db push`, `functions deploy`, `secrets set`, `link`) target a
linked/hosted project — never run them unattended; a Bash guard hook blocks them.

## Coding standards

- **SQL:** match the existing migration idioms — lowercase keywords, an explicit
  `enable row level security` + a policy on every new table, `SECURITY DEFINER` only
  where a function must cross RLS and always with `set search_path = public`. Comment WHY.
- **TypeScript (edge functions):** Deno with `jsr:`/`npm:` imports, no build step; keep
  the existing style — explicit CORS map, service role via env, validate + size-cap all
  input, never trust client-supplied hashes. No new dependencies beyond `supabase-js`.
- Small, reviewable diffs; comment the security-relevant reasoning.

## Security (treat as load-bearing)

- **RLS on every user table.** New tables MUST enable RLS and add a policy; a table with
  RLS on and no policy denies all, a table with RLS off is wide open.
- **`SECURITY DEFINER` review.** Such functions run as owner and bypass RLS; keep
  `set search_path`, revoke EXECUTE from public/anon where not needed (see the hardening
  migration), and never widen scope silently.
- **Storage policies live in migrations,** not the dashboard; per-user isolation keys on
  the owner path segment (`(storage.foldername(name))[1] = auth.uid()`).
- **Service-role key is edge-function-only.** It bypasses RLS; it lives in the function
  runtime env — never in the client, never in a migration, never committed.
- **Never read or commit secrets.** `.env`/`.env.*` are never read or committed (only
  `.env.example` is tracked); the anon key is safe to expose, the service-role/DB/SMTP/
  Patreon secrets are not.
- **Edge-function authz.** GET-public functions still verify the JWT manually on writes;
  validate every field, cap body size, and compute trust-sensitive values (hashes)
  server-side.

## Pitfalls

- **Applied migrations are IMMUTABLE.** Never edit an existing file under
  `supabase/migrations/` — a changed migration diverges every already-migrated database.
  Always add a NEW timestamped migration. An Edit/Write guard hook enforces this.
- **Buckets and policies live in migrations,** not the dashboard — changing them by hand
  on a project drifts from the tracked schema.
- **Quota functions were deliberately hardened** (EXECUTE revoked from public/anon);
  don't "fix" that by re-granting.
- **No CI gate** — the Deno unit tests run only when someone runs them, and the pgTAP suites need
  the local stack; report exactly which of them you ran, never "the gate is green".

## Git and commits

- Commit as `sKuhLight <sKuhLight@users.noreply.github.com>`.
- Message format: `<scope>: <imperative>`. **No AI/Claude attribution anywhere.**
- Commit/push only when explicitly asked.
- Never commit `.env`/`.env.*` (except `.env.example`), `CLAUDE.local.md`, `.mcp.json`,
  or `.claude/settings.local.json`.

## Task tracking (Plane — MANDATORY)

Plane is the single source of truth for all active and planned work in this repo: for
every non-trivial task, search for an existing item first, create one if missing, set it
In Progress when work starts, and comment + close it on completion. The Plane project
coordinates (UUIDs, server) and the workspace-private policy live in **`CLAUDE.local.md`**
(gitignored) — they are intentionally kept out of this committable file.
