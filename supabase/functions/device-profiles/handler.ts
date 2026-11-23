// Request handling for `device-profiles` (the v1 shared profile store), with every side effect behind `Deps` so the
// whole flow — above all the RANKING of candidate rows — is testable with in-memory fakes (handler.test.ts).
// index.ts wires the Supabase adapter.
//
// Global device-definition profile store (AXISCLOUD-2). Profiles are derived `BuiltCache` docs
// (ForgeFX deviceCache.ts → forgefx-midi buildCache), identical for every device of the same model on
// the same firmware — NOT user data. First user on a new firmware uploads; everyone else downloads.
//
//   GET  ?model=<int>&firmware=<string>[&schema=<int>]  → the BEST matching profile + metadata (404 if none).
//        Public. "Best" is NOT "newest" (PROFILE_ORDER): an editor-cache profile before a live-walk one, then the
//        profile with more (family, parameter id) ranges (`row_count`, computed by the database from the stored
//        document), then the OLDEST. A truncated live walk uploaded later therefore never displaces a complete
//        profile. The flip side: a same-schema derivation FIX (say corrected displayMax values or enum labels
//        re-derived from the same editor cache: same row_count, new content hash) no longer reaches v1 clients — the
//        older row wins the tie, and a fix that REMOVES wrong entries even loses on row_count. It reaches them only
//        through a schema bump or by evicting the older rows (README, v1 maintainer runbook); before this ranking the
//        newest upload won. `schema` selects the profile schema (`profile.meta.schema`, the codec's CACHE_SCHEMA) the caller
//        can use: the best row of THAT schema is returned, so clients on different schemas never hide each other's
//        profiles. Without `schema` (clients that predate the parameter) only unstamped rows and schemas in
//        LEGACY_SCHEMAS (<= 1) are eligible. Schema 1 is the first stamped format; its document shape is the same as
//        the unstamped one, so a pre-schema client can apply it (it may carry derivation fixes that client lacks,
//        never a changed format).
//        The response shape is the v1 one (RESPONSE_COLUMNS); `row_count` is an ordering key, not part of it.
//   POST { model, firmware, source, profile }  → validate + hash server-side + insert. Requires a JWT of an ACCOUNT
//        (anonymous sessions: 403 account-required).
//
// verify_jwt is OFF for this function (config.toml) so GET stays public; POST verifies the caller's token
// manually. Writes use the service role — the table has no client-facing write policy.
//
// Responses (JSON): GET 200 <row> | 400 { error } | 404 { error: "not found" } | 500 { error };
//   POST 201 { ok, id, model, firmware, content_hash, source, created_at } | 200 { deduped, contentHash } |
//   400 { error } | 401 unauthorized | 403 account-required | 413 payload too large | 429 rate limited | 500 { error }.
import { corsHeaders } from "../_shared/cors.ts";

// Reject bodies larger than this before parsing (a BuiltCache is well under a MB; this bounds abuse).
export const MAX_BODY_BYTES = 6 * 1024 * 1024;
// Profile schemas an old client (one that sends no `schema` parameter) may be served, besides unstamped rows:
// schema 1 keeps the unstamped document shape. A later schema that changes the shape must not be added here.
export const LEGACY_SCHEMAS: readonly number[] = [0, 1];
// Upper bound for a requested schema number (rejects junk; real schemas are small integers).
export const MAX_SCHEMA = 1_000_000;
// Per-user insert budget: at most this many NEW profiles per rolling hour (dedups don't count against it).
export const RATE_LIMIT_PER_HOUR = 10;
const RATE_WINDOW_MS = 60 * 60 * 1000;

/** The columns a v1 client receives (unchanged since the store went live). */
export const RESPONSE_COLUMNS = ["id", "model", "firmware", "content_hash", "profile", "source", "record_count", "created_at"] as const;

// ─────────────────────────────────────────── ranking ───────────────────────────────────────────

/** Columns of `device_profiles` the ranking may order by. */
export type OrderColumn = "source" | "row_count" | "created_at";

/** One ORDER BY term, in PostgREST terms (`nullsFirst: false` = NULLS LAST). */
export interface OrderTerm {
  column: OrderColumn;
  ascending: boolean;
  nullsFirst: boolean;
}

/**
 * The v1 ranking, best row first (migrations/20261201130000_device_profiles_ranking.sql explains the columns):
 *  1. `source` ASCENDING = editor-cache before live-walk. That is alphabetical order, and it is only sound because
 *     the table's `source` check allows exactly these two values (pinned by the pgTAP suite and by handler.test.ts) —
 *     widen the check and this order together.
 *  2. `row_count` DESCENDING: the profile defining more (family, parameter id) ranges is the more complete one
 *     (NULL last: a row without a server count never outranks one with it).
 *  3. `created_at` ASCENDING: on a tie the OLDEST row stays, so an equal newcomer never displaces an incumbent.
 * Never by date first — that is what let a truncated live walk displace a complete profile.
 */
export const PROFILE_ORDER: readonly OrderTerm[] = [
  { column: "source", ascending: true, nullsFirst: false },
  { column: "row_count", ascending: false, nullsFirst: false },
  { column: "created_at", ascending: true, nullsFirst: false }
];

// ─────────────────────────────────────────── seam ───────────────────────────────────────────

/** What GET asks the store for: the candidates of (model, firmware[, schema]), the BEST one by `order`. */
export interface ProfileFilter {
  model: number;
  firmware: string;
  /** Requested schema (`profile.meta.schema`); null = a client that sends none: unstamped rows and `legacySchemas`. */
  schema: number | null;
  legacySchemas: readonly number[];
  order: readonly OrderTerm[];
}

/**
 * The PostgREST query-builder calls the store adapter makes (supabase-js's builder has them, each returning the
 * builder). Structural, so this module stays free of supabase-js; query.test.ts drives the real supabase-js builder
 * through applyProfileFilter and pins the request it sends.
 */
interface ProfileQuery {
  eq(column: string, value: string | number): ProfileQuery;
  or(filters: string): ProfileQuery;
  order(column: string, options: { ascending: boolean; nullsFirst: boolean }): ProfileQuery;
}

/**
 * Narrow a `device_profiles` query to the candidates of `f` and order it by `f.order` (the adapter adds `limit 1`).
 * With PROFILE_ORDER, PostgREST receives `order=source.asc.nullslast,row_count.desc.nullslast,created_at.asc.nullslast`.
 * `Q` is unconstrained on purpose: checking supabase-js's deeply generic builder against ProfileQuery (even loosely)
 * exceeds TypeScript's instantiation depth (TS2589). query.test.ts is the guard instead.
 */
export function applyProfileFilter<Q>(query: Q, f: ProfileFilter): Q {
  let q = (query as unknown as ProfileQuery).eq("model", f.model).eq("firmware", f.firmware);
  // Schema filter on the stored profile's meta.schema (jsonb path `profile->meta->>schema`, compared as text).
  q = f.schema !== null
    ? q.eq("profile->meta->>schema", String(f.schema))
    : q.or(`profile->meta->>schema.is.null,profile->meta->>schema.in.(${f.legacySchemas.join(",")})`);
  for (const t of f.order) q = q.order(t.column, { ascending: t.ascending, nullsFirst: t.nullsFirst });
  return q as unknown as Q;
}

/** A stored profile as GET returns it (snake_case, as the table names the columns). */
export interface ProfileRow {
  id: string;
  model: number;
  firmware: string;
  content_hash: string;
  profile: Record<string, unknown>;
  source: "live-walk" | "editor-cache";
  record_count: number | null;
  created_at: string;
}

/** What POST inserts. `row_count` is NOT here: the database computes it from `profile` (a stored generated column). */
export interface NewProfile {
  model: number;
  firmware: string;
  content_hash: string;
  profile: Record<string, unknown>;
  source: "live-walk" | "editor-cache";
  record_count: number | null;
  created_by: string;
}

/** The columns POST answers with after an insert. */
export interface InsertedProfile {
  id: string;
  model: number;
  firmware: string;
  content_hash: string;
  source: string;
  created_at: string;
}

export type InsertResult =
  | { kind: "inserted"; row: InsertedProfile }
  // unique (model, firmware, content_hash): an identical profile is already stored
  | { kind: "duplicate" };

export interface Deps {
  /** Resolve the user from the request's Authorization header (Auth server round trip); null = not a valid session. */
  authenticate(authorization: string): Promise<{ id: string; isAnonymous: boolean } | null>;
  /** The best candidate by `filter.order`, or null. Throws on a database error (→ 500). */
  selectBestProfile(filter: ProfileFilter): Promise<ProfileRow | null>;
  /** How many profiles this user inserted since `sinceIso`. */
  countRecentInserts(userId: string, sinceIso: string): Promise<number>;
  /** Insert; `duplicate` for the unique violation (23505), a throw for anything else. */
  insertProfile(row: NewProfile): Promise<InsertResult>;
}

export interface HandlerConfig {
  maxBodyBytes: number;
  rateLimitPerHour: number;
  now: () => number;
}

export const DEFAULT_CONFIG: HandlerConfig = {
  maxBodyBytes: MAX_BODY_BYTES,
  rateLimitPerHour: RATE_LIMIT_PER_HOUR,
  now: () => Date.now()
};

// ─────────────────────────────────────────── helpers ───────────────────────────────────────────

// Browser clients (supabase-js, or fetch with its headers) also send `apikey` / `x-client-info`: see _shared/cors.ts.
const cors = corsHeaders("GET, POST, OPTIONS");
const json = { ...cors, "Content-Type": "application/json" };

function reply(status: number, body: unknown, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), { status, headers: extra ? { ...json, ...extra } : json });
}

/** sha256 hex of a string (server-computed — a client-supplied hash is never trusted). */
async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Canonical JSON: objects with sorted keys, recursively. Hashing this makes dedup independent of the
 *  key order a client happened to serialize with — identical content always lands on the same row. */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (isPlainObject(v)) {
    const keys = Object.keys(v).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmptyObject(v: unknown): boolean {
  return isPlainObject(v) && Object.keys(v).length > 0;
}

/**
 * Plausibility gate for a BuiltCache doc (forgefx-midi src/cache/buildProfile.ts → BuiltCache extends
 * BuiltCacheData). The always-derived essential tables are `ranges`, `rangeSections` and `rosters`
 * (family-keyed maps that any real device build populates); `enumOverrides` and `cabIrs` must be present
 * as objects but may legitimately be empty for some devices. `meta` carries `recordCount` (number) and
 * `source` ('live' | 'bytes'). We reject anything missing the essentials — this keeps junk out of the
 * shared store without hard-coding device specifics.
 */
export function validateProfile(p: unknown): string | null {
  if (!isPlainObject(p)) return "profile must be an object";
  if (!nonEmptyObject(p.ranges)) return "profile.ranges missing or empty";
  if (!nonEmptyObject(p.rangeSections)) return "profile.rangeSections missing or empty";
  if (!nonEmptyObject(p.rosters)) return "profile.rosters missing or empty";
  if (!isPlainObject(p.enumOverrides)) return "profile.enumOverrides must be an object";
  if (!isPlainObject(p.cabIrs)) return "profile.cabIrs must be an object";
  if (!isPlainObject(p.meta)) return "profile.meta must be an object";
  const meta = p.meta as Record<string, unknown>;
  if (typeof meta.recordCount !== "number") return "profile.meta.recordCount must be a number";
  if (meta.source !== "live" && meta.source !== "bytes") return "profile.meta.source invalid";
  return null;
}

// ─────────────────────────────────────────── handler ───────────────────────────────────────────

export async function handleRequest(req: Request, deps: Deps, config: HandlerConfig = DEFAULT_CONFIG): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    if (req.method === "GET") return await handleGet(req, deps);
    if (req.method === "POST") return await handlePost(req, deps, config);
    return new Response("method not allowed", { status: 405, headers: cors });
  } catch (e) {
    // A database/Auth failure behind the seam. v1 has always answered it with the error text (no stack, no secrets).
    return reply(500, { error: e instanceof Error ? e.message : String(e) });
  }
}

/** GET: the best profile for (model, firmware[, schema]). Public, cacheable. */
async function handleGet(req: Request, deps: Deps): Promise<Response> {
  const q = new URL(req.url).searchParams;
  const model = Number(q.get("model"));
  const firmware = q.get("firmware") ?? "";
  if (!Number.isInteger(model) || model < 1 || model > 255 || !firmware) {
    return reply(400, { error: "bad request: model (1..255) and firmware required" });
  }
  // Optional schema filter on the stored profile's meta.schema (jsonb path `profile->meta->>schema`,
  // compared as text; no index needed — rows per (model, firmware) are few).
  const schemaRaw = q.get("schema");
  let schema: number | null = null;
  if (schemaRaw !== null) {
    schema = /^\d{1,7}$/.test(schemaRaw) ? Number(schemaRaw) : NaN;
    if (!Number.isInteger(schema) || schema < 1 || schema > MAX_SCHEMA) {
      return reply(400, { error: `bad request: schema must be an integer 1..${MAX_SCHEMA}` });
    }
  }
  const row = await deps.selectBestProfile({ model, firmware, schema, legacySchemas: LEGACY_SCHEMAS, order: PROFILE_ORDER });
  if (!row) return reply(404, { error: "not found" });
  // Exactly the v1 columns: whatever else the store returned (row_count, a future column) is not part of the answer.
  const out: Record<string, unknown> = {};
  for (const c of RESPONSE_COLUMNS) out[c] = (row as unknown as Record<string, unknown>)[c];
  return reply(200, out, { "Cache-Control": "public, max-age=300" });
}

/** POST: upload a profile. Requires a valid ACCOUNT session. */
async function handlePost(req: Request, deps: Deps, config: HandlerConfig): Promise<Response> {
  const user = await deps.authenticate(req.headers.get("Authorization") ?? "");
  if (!user) return reply(401, { error: "unauthorized" });
  // Publishing to the SHARED store needs an account. Anonymous sessions (enabled project-wide for editor-cache
  // uploads) are valid JWTs too, and can be minted at will — they would make the per-user rate limit below
  // meaningless for a store whose rows every client downloads.
  if (user.isAnonymous) return reply(403, { error: "account-required" });

  // Cheap pre-parse size guard (Content-Length is advisory but bounds the common case).
  const len = Number(req.headers.get("Content-Length") ?? 0);
  if (len && len > config.maxBodyBytes) return reply(413, { error: "payload too large" });

  const raw = await req.text();
  if (raw.length > config.maxBodyBytes) return reply(413, { error: "payload too large" });
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return reply(400, { error: "invalid JSON" });
  }
  if (!isPlainObject(parsed)) return reply(400, { error: "body must be a JSON object" });
  const { model, firmware, source, profile } = parsed;

  if (typeof model !== "number" || !Number.isInteger(model) || model < 1 || model > 255) {
    return reply(400, { error: "model must be an integer 1..255" });
  }
  if (typeof firmware !== "string" || !/^\d+\.\d+/.test(firmware)) {
    return reply(400, { error: "firmware must match \\d+\\.\\d+" });
  }
  if (source !== "live-walk" && source !== "editor-cache") {
    return reply(400, { error: "source must be 'live-walk' or 'editor-cache'" });
  }
  const bad = validateProfile(profile);
  if (bad) return reply(400, { error: bad });
  const doc = profile as Record<string, unknown>;
  // The API source kind must agree with what the profile says built it: live-walk ↔ codec 'live',
  // editor-cache ↔ codec 'bytes'. Prevents mislabeled rows in the shared store.
  const metaSource = (doc.meta as Record<string, unknown>).source;
  const expected = source === "live-walk" ? "live" : "bytes";
  if (metaSource !== expected) {
    return reply(400, { error: `source '${source}' does not match profile.meta.source '${metaSource}'` });
  }

  // Rate limit: reject if this user already inserted >= N profiles in the last hour.
  const since = new Date(config.now() - RATE_WINDOW_MS).toISOString();
  const count = await deps.countRecentInserts(user.id, since);
  if (count >= config.rateLimitPerHour) return reply(429, { error: "rate limited" });

  // Hash the canonical (sorted-key) profile JSON server-side — never trust a client hash. Nothing else of the body is
  // stored either: a client-supplied `row_count`, `content_hash` or `created_by` is ignored (row_count is computed
  // by the database from the profile; see the ranking migration).
  const contentHash = await sha256Hex(canonicalJson(doc));
  const recordCount = (doc.meta as { recordCount?: unknown }).recordCount;

  const res = await deps.insertProfile({
    model,
    firmware,
    content_hash: contentHash,
    profile: doc,
    source,
    record_count: typeof recordCount === "number" ? recordCount : null,
    created_by: user.id
  });
  // An identical (model, firmware, content) profile already exists.
  if (res.kind === "duplicate") return reply(200, { deduped: true, contentHash });
  return reply(201, { ok: true, ...res.row });
}
