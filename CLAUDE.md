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

**Edge functions** (`supabase/functions/*/index.ts`, Deno + `supabase-js`):
- `delete-account` — GDPR erase. `verify_jwt = true`; identifies the caller from their
  token, then removes their blobs + rows + auth user with the service role.
- `gc-blobs` — orphan-blob sweep. `verify_jwt = false`, gated by the `GC_SECRET` header;
  deletes `preset-blobs` objects not referenced by any `preset_versions.blob_path`,
  skipping objects <24 h old. `?dry=1` reports without deleting.
- `device-profiles` — shared profile store. `verify_jwt = false` (GET is public); POST
  verifies the JWT manually, validates + size-caps the body, computes the content hash
  server-side, rate-limits, and inserts with the service role.

**Storage buckets:** `preset-blobs` (private, per-user path RLS, per-object size cap) and
`debug-reports` (private, insert-only).

**RLS / quota model:** every user table has RLS with `auth.uid() = user_id`, so the anon/
publishable key is safe to expose — RLS protects every row. Quotas are enforced by a
`SECURITY DEFINER` trigger as a backstop (the client pre-flights); paid users
(`subscriptions.active` within period) bypass. `device_profiles` is the one public-read,
service-role-write table (shared derived data, not user data).

## Commands (Supabase CLI)

No local CLI, Deno, or Docker is assumed — invoke the CLI through `npx`:

- `npx --yes supabase@latest start` / `stop` — local stack (**needs Docker running**).
- `npx --yes supabase@latest db reset` — rebuild the local DB from `migrations/` + seed.
- `npx --yes supabase@latest functions serve <name>` — run an edge function locally.
- `npx --yes supabase@latest db diff` — diff the local DB vs migrations (to author a new one).
- `npx --yes supabase@latest status` — inspect the running local stack.

**There is no cheap automated test gate in this repo yet** — no package.json, no CI, no
unit tests. Verification today means running the local stack (Docker) and exercising the
functions/SQL by hand. Do not claim a passing gate that does not exist. (Follow-up
tracked in Plane.)

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
- **No test gate** — a green typecheck/test does not exist; don't imply one.

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
