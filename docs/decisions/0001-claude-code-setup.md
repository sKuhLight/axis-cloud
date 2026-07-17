# ADR-0001: Claude Code baseline setup for axis-cloud

- **Status:** Accepted
- **Date:** 2026-07-17
- **Owners:** axis-cloud maintainers

## Context

axis-cloud is the optional Supabase cloud-sync backend for the Axis editor
(Postgres + Auth + Storage), defined entirely as SQL migrations and Deno edge
functions. It has properties that make unassisted automated edits risky:

- **Immutable migrations.** The schema is a set of timestamp-ordered migrations
  under `supabase/migrations/`. Editing an already-applied migration diverges every
  database that has run it — a change must always be a NEW migration, never an edit.
- **Security-critical surface.** Row-Level Security policies, `SECURITY DEFINER`
  functions, Storage bucket policies, and edge-function authz are the isolation
  boundary between users. A missing policy or a leaked service-role key is a data
  breach, not a style nit.
- **No automated test gate.** There is no `package.json`, no CI, and no unit tests.
  Verification means running the local stack (Docker) and exercising the SQL/functions
  by hand — so an agent can neither lean on nor be caught by a green gate.

Separately, the project family that includes this repo adopted a single central task
tracker (Plane) so that active and planned work — goals, rationale, and status — is
recorded in one place, and a policy that workspace-private coordinates never enter
committable files.

## Decision

Adopt the family-wide Claude Code baseline for this repo, tailored to a Supabase
backend:

- **A committable `CLAUDE.md` plus a private, gitignored `CLAUDE.local.md`.** The
  committable file is the full working guide (architecture, commands, coding standards,
  security, pitfalls, git rules). The private file holds the workspace-private
  coordinates — Plane project UUIDs, the self-hosted Plane URL, and sibling-workspace
  script paths — that must never appear in tracked files. The `CLAUDE.md` line was
  removed from `.gitignore` while `CLAUDE.local.md` stays ignored. This split is why no
  private coordinate lives in any tracked file even though the working guide is now
  public.
- **`.claude/settings.json`** with conservative permissions: read-only git/rg/grep plus
  the read-only `supabase status`; remote-mutating Supabase ops (`db push`, `functions
  deploy`, `secrets`, `link`) and `git push` require confirmation; `.env`/key files and
  edits to `supabase/migrations/**` are denied.
- **Two `PreToolUse` guard hooks.** `guard-bash.sh` blocks destructive commands
  (`rm -rf /` or `~`, force-push), remote-mutating Supabase commands (including when run
  via `npx supabase`), and in-place writes onto migrations. `guard-migrations.sh` blocks
  any Edit of a file under `supabase/migrations/` and any Write that would overwrite an
  existing migration — enforcing migration immutability at execution time, as a backstop
  to the settings deny rule.
- **Two subagents:** `reviewer` (read-only diff review focused on RLS completeness,
  SECURITY DEFINER review, storage-bucket policies, quota logic, edge-function authz, and
  secret exposure) and `explorer` (read-only schema/function discovery). No
  `test-runner` agent is provided, because there is no test gate to run — inventing one
  would be dishonest.
- **A `/plan-feature` command** that plans changes without editing code and enforces the
  Plane task-tracking step first.
- **An ADR log** under `docs/decisions/` (this file and the template).

## Alternatives

- **No tooling (status quo).** Rejected: the migration-immutability and RLS footguns
  keep recurring with no guardrail to catch them.
- **README-only conventions.** Rejected: documented conventions are not enforced, so
  automated and human edits still violate them.
- **A single gitignored `CLAUDE.md` (as some sibling repos use).** Rejected here: this
  repo is source-available and benefits from a committable, reviewable working guide;
  keeping the guide private would hide it from self-hosters. The private/committable
  split gives both a public guide and private coordinates.
- **A fabricated test gate.** Rejected: there is no test suite, and pretending one
  exists would make agents assert verification they never ran. The absence is documented
  instead, with a follow-up tracked in Plane.

## Consequences

- Agents operate with enforced guardrails (permissions plus hooks), not just advice,
  reducing the risk of edited migrations, missing RLS, and leaked secrets.
- Contributors and self-hosters get the conventions written down and reviewable in a
  tracked `CLAUDE.md`, while private coordinates stay out of the repo.
- The lack of an automated verification gate remains a real gap; establishing one (for
  example a scripted local-stack smoke test) is a follow-up tracked in Plane.
