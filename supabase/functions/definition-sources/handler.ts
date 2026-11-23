// Request handling for `definition-sources` (shared device definitions, cloud v2), with every side effect behind
// `Deps` so the whole flow is testable with in-memory fakes (handler.test.ts). index.ts wires the Supabase adapter.
//
// What is shared: ONE sanitized raw definition source per row (an editor cache's records, or a live device read), per
// (model, firmware, kind, fact hash). Public rows carry no user link; who shared what is private (contributions) and
// readable by the uploader only (GET /mine). Ranking, tiers and limits live in SQL
// (migrations/20261201120000_definition_sources.sql); this layer validates, sanitizes and computes the facts.
//
//  GET   /definition-sources?model=17&firmware=13.0[&rawFormat=1]          public, no auth
//     200 { model, firmware, sources: SourceSummary[], alternatives: { 'editor-cache', 'live-full', 'live-readonly' },
//           allowAnonymous }
//         best servable row per kind (none: `sources: []`), Cache-Control: public, max-age=300. `alternatives` =
//         servable rows of that kind INCLUDING the one listed. Dates are UTC days (`YYYY-MM-DD`). `allowAnonymous` =
//         whether contribute/report accept anonymous sessions (says nothing about readonly/off).
//  GET   /definition-sources/source/<id>                                     public, no auth
//     200 { id, model, firmware, kind, rawFormat, factHash, tier, quality, summary, source }
//         Cache-Control: public, max-age=86400. 404 not-found for a missing, rejected, quarantined or orphaned row.
//  POST  /definition-sources                                                 Bearer (account or anonymous session)
//       { model, firmware, kind, rawFormat, source, app?, consentAt, consentVersion }
//     201 { sourceId, factHash, created: true, deduped: false, confirmed: false, tier, contributors, networks }
//     200 { sourceId, factHash, created: false, deduped: true, confirmed, tier, contributors, networks }
//         (deduped = the facts were in already; confirmed = this call added a contributor)
//  POST  /definition-sources/withdraw  { sourceId } | { all: true, model?, firmware? }   Bearer
//     200 { withdrawn, deletedSources }   own linked contributions only; an unknown/foreign sourceId -> 404
//  GET   /definition-sources/mine                                            Bearer
//     200 { contributions: [{ id, sourceId, model, firmware, kind, factHash, createdAt, linkedUntil }] }  (≤ 100)
//  POST  /definition-sources/report  { sourceId, verdict, checked, answered, mismatches, app? }   Bearer
//     200 { ok: true, quarantined }       (never creates a session: the client sends it only when it has one)
//  (`?action=withdraw|mine|report` works too, for proxies that drop the path.)
//
//  Errors (JSON { error, message?, … }):
//   400 invalid-request | invalid-json | empty-body | consent-required     401 unauthorized
//   403 account-required (contribute/report by an anonymous session while anonymous sharing is off)
//   404 not-found     405 method-not-allowed     409 unsupported-model | rejected (facts the maintainer rejected)
//   413 too-large { limit, bytes? }
//   422 invalid-source { path, reason } | contains-user-data | tolerant-source | firmware-inconsistent |
//       version-mismatch | implausible | unsupported-raw-format
//   429 rate-limited | quota-exceeded { scope: 'uploader' | 'network', retryAfterSeconds } + Retry-After
//   503 paused (DEFINITION_SOURCES not `on` for writes / `off` for reads; network-key secret missing, short or
//       the editor-cache one) | auth-unavailable (the Auth server could not be asked: retry, + Retry-After)
//   500 internal
//
// Availability: withdraw and /mine (erasure and access) work whatever the switches say; reads stop only at `off`;
// contribute and report need `on` and the network-key secret.
import { CORS_ALLOW_HEADERS } from "../_shared/cors.ts";
import { clientNetwork, DEFAULT_IP_HEADERS, describeClientHeaders, networkKey } from "../_shared/network.ts";
import { computeFacts, type FactKind } from "./facts.ts";
import {
  CONTRIBUTE_MODELS,
  type Contribution,
  type ContributionOptions,
  looksLikeJwt,
  MAX_CONTRIBUTION_BYTES,
  MAX_JSON_BODY_BYTES,
  MIN_IP_SALT_LENGTH,
  MINE_LIMIT,
  LIST_MAX_AGE_SECONDS,
  NET_QUOTA_BYTES,
  NET_RATE_LIMIT_PER_WINDOW,
  NET_REPORT_RATE_LIMIT_PER_WINDOW,
  NETWORK_DOMAIN,
  type Parsed,
  parseContribution,
  parseListQuery,
  parseReportRequest,
  parseRowId,
  parseWithdrawRequest,
  QUOTA_BYTES,
  QUOTA_WINDOW_SECONDS,
  RATE_LIMIT_PER_WINDOW,
  RATE_WINDOW_SECONDS,
  readBodyCapped,
  REPORT_RATE_LIMIT_PER_WINDOW,
  REPORT_WINDOW_SECONDS,
  SHARED_KINDS,
  SOURCE_MAX_AGE_SECONDS,
  type WithdrawRequest
} from "./validate.ts";

export type Tier = "official" | "verified" | "candidate" | "rejected";

/** A row of select_definition_sources (the best servable row per kind; day-granular dates only). */
export interface ListedSourceRow {
  id: string;
  kind: FactKind;
  rawFormat: number;
  factHash: string;
  tier: Tier;
  quality: number;
  contributors: number;
  networks: number;
  spotPasses: number;
  spotFailures: number;
  /** UTC day `YYYY-MM-DD`. */
  firstSeenDay: string;
  lastConfirmedDay: string | null;
  bytes: number;
  summary: Record<string, unknown>;
  alternatives: number;
}

/** A source row by id, with the columns the servability check needs (never the precise timestamps). */
export interface SourceRow {
  id: string;
  model: number;
  firmware: string;
  kind: FactKind;
  rawFormat: number;
  factHash: string;
  tier: Tier;
  quality: number;
  summary: Record<string, unknown>;
  source: Record<string, unknown>;
  pinned: boolean;
  contributors: number;
  quarantined: boolean;
}

export interface ContributeArgs {
  userId: string;
  /** HMAC of the client network (validate.ts NETWORK_DOMAIN) — never the address. */
  networkKey: string;
  model: number;
  firmware: string;
  kind: FactKind;
  rawFormat: number;
  factHash: string;
  source: Record<string, unknown>;
  summary: Record<string, unknown>;
  quality: number;
  coverageScore: number;
  bytes: number;
  app: Record<string, string>;
  consentAt: string;
  consentVersion: number;
  maxPerWindow: number;
  windowSeconds: number;
  netMaxPerWindow: number;
  quotaBytes: number;
  quotaWindowSeconds: number;
  netQuotaBytes: number;
}

export type Limited = { kind: "limited"; reason: "rate" | "quota"; scope: "uploader" | "network"; retryAfterSeconds: number };

export type ContributeResult =
  | {
    kind: "ok";
    sourceId: string;
    created: boolean;
    deduped: boolean;
    confirmed: boolean;
    tier: Tier;
    contributors: number;
    networks: number;
  }
  | Limited
  | { kind: "rejected" };

export interface WithdrawArgs {
  userId: string;
  sourceId: string | null;
  model: number | null;
  firmware: string | null;
}

export interface ReportArgs {
  userId: string;
  networkKey: string;
  sourceId: string;
  verdict: "passed" | "failed";
  checked: number;
  answered: number;
  mismatches: number;
  app: Record<string, string>;
  maxPerWindow: number;
  netMaxPerWindow: number;
  windowSeconds: number;
}

export type ReportResult = { kind: "ok"; quarantined: boolean } | { kind: "not-found" } | Limited;

/** One entry of GET /mine. */
export interface ContributionSummary {
  id: string;
  sourceId: string;
  model: number;
  firmware: string;
  kind: FactKind;
  factHash: string | null;
  createdAt: string;
  linkedUntil: string;
}

export interface Deps {
  /** Resolve the user from the bearer token (Auth server round trip); null = invalid/expired token;
   *  "unavailable" = the Auth server could not answer (network, 5xx, rate limit: retryable, never a 401). */
  authenticate(accessToken: string): Promise<{ id: string; isAnonymous: boolean } | null | "unavailable">;
  /** select_definition_sources(model, firmware, rawFormatMax). */
  selectSources(model: number, firmware: string, rawFormatMax: number): Promise<ListedSourceRow[]>;
  /** A source by id (the adapter already filters servable rows; the handler checks again). */
  getSource(id: string): Promise<SourceRow | null>;
  /** contribute_definition_source (SQLSTATEs mapped with contributeOutcomeFromSqlError). */
  contribute(args: ContributeArgs): Promise<ContributeResult>;
  /** withdraw_definition_contributions. */
  withdraw(args: WithdrawArgs): Promise<{ withdrawn: number; deletedSources: number }>;
  /** The caller's linked contributions, newest first. */
  listMine(userId: string, limit: number): Promise<ContributionSummary[]>;
  /** report_definition_source (SQLSTATEs mapped with reportOutcomeFromSqlError). */
  report(args: ReportArgs): Promise<ReportResult>;
}

/** DEFINITION_SOURCES: `on` (default), `readonly` (reads, withdraw and /mine only), `off` (withdraw and /mine only). */
export type Mode = "on" | "readonly" | "off";

export interface HandlerConfig {
  mode: Mode;
  /** Anonymous sessions may contribute and report (DEFINITION_SOURCES_ALLOW_ANONYMOUS; default yes). */
  allowAnonymous: boolean;
  /** Secret of the network key (DEFINITION_SOURCES_IP_SALT). Without a strong one, writes are paused. */
  ipSalt: string | null;
  /** Request headers the client address is read from, in order (_shared/network.ts clientNetwork). */
  ipHeaders: readonly string[];
  maxContributionBytes: number;
  maxJsonBodyBytes: number;
  rateLimitPerWindow: number;
  netRateLimitPerWindow: number;
  rateWindowSeconds: number;
  quotaBytes: number;
  netQuotaBytes: number;
  quotaWindowSeconds: number;
  reportRateLimitPerWindow: number;
  netReportRateLimitPerWindow: number;
  reportWindowSeconds: number;
  contributeModels: readonly number[];
  /** Validation options (tests lower the plausibility floor). */
  validation: ContributionOptions;
  now: () => number;
  /** Function log (maintainer-only). Never receives addresses, tokens or source content. */
  log: (level: "info" | "warn", message: string) => void;
}

export const DEFAULT_CONFIG: HandlerConfig = {
  mode: "on",
  allowAnonymous: true,
  ipSalt: null,
  ipHeaders: DEFAULT_IP_HEADERS,
  maxContributionBytes: MAX_CONTRIBUTION_BYTES,
  maxJsonBodyBytes: MAX_JSON_BODY_BYTES,
  rateLimitPerWindow: RATE_LIMIT_PER_WINDOW,
  netRateLimitPerWindow: NET_RATE_LIMIT_PER_WINDOW,
  rateWindowSeconds: RATE_WINDOW_SECONDS,
  quotaBytes: QUOTA_BYTES,
  netQuotaBytes: NET_QUOTA_BYTES,
  quotaWindowSeconds: QUOTA_WINDOW_SECONDS,
  reportRateLimitPerWindow: REPORT_RATE_LIMIT_PER_WINDOW,
  netReportRateLimitPerWindow: NET_REPORT_RATE_LIMIT_PER_WINDOW,
  reportWindowSeconds: REPORT_WINDOW_SECONDS,
  contributeModels: CONTRIBUTE_MODELS,
  validation: {},
  now: () => Date.now(),
  log: (level, message) => (level === "warn" ? console.warn(message) : console.log(message))
};

// ─────────────────────────────────────────── Auth outage (used by index.ts) ───────────────────────────────────────────

/** Seconds a client should wait after the Auth server could not be asked. */
export const AUTH_RETRY_AFTER_SECONDS = 30;

/**
 * Is an error from `auth.getUser(jwt)` an OUTAGE (retry later) rather than a verdict on the token? A network failure
 * (`AuthRetryableFetchError`, status 0), a 5xx, a 429 or an error without an HTTP status (an unparsable gateway
 * page) is an outage; a 4xx (bad, expired or revoked token, deleted user) is a verdict. Answering an outage with
 * 401 would make a client drop a perfectly good session (and an anonymous install mint a new identity).
 */
export function isAuthOutage(e: { name?: string; status?: number } | null | undefined): boolean {
  if (!e) return false;
  if (e.name === "AuthRetryableFetchError") return true;
  const status = e.status;
  if (typeof status !== "number" || status === 0) return true;
  return status === 429 || status >= 500;
}

// ─────────────────────────────────────────── SQLSTATE mapping (used by index.ts) ───────────────────────────────────────────

type SqlErrorLike = { code?: string; details?: string | null };

function retrySeconds(e: SqlErrorLike): number {
  const n = Number.parseInt(String(e.details ?? ""), 10);
  return Number.isFinite(n) && n > 0 ? n : 60;
}

/**
 * contribute_definition_source's custom SQLSTATEs (DETAIL = retry seconds for the limits): XQ001 uploader rate,
 * XQ002 uploader byte quota, XQ005 network rate, XQ006 network byte quota, XQ007 maintainer-rejected facts.
 * null = not one of them (the caller rethrows: 500).
 */
export function contributeOutcomeFromSqlError(e: SqlErrorLike): Limited | { kind: "rejected" } | null {
  switch (e.code) {
    case "XQ001":
      return { kind: "limited", reason: "rate", scope: "uploader", retryAfterSeconds: retrySeconds(e) };
    case "XQ002":
      return { kind: "limited", reason: "quota", scope: "uploader", retryAfterSeconds: retrySeconds(e) };
    case "XQ005":
      return { kind: "limited", reason: "rate", scope: "network", retryAfterSeconds: retrySeconds(e) };
    case "XQ006":
      return { kind: "limited", reason: "quota", scope: "network", retryAfterSeconds: retrySeconds(e) };
    case "XQ007":
      return { kind: "rejected" };
    default:
      return null;
  }
}

/** report_definition_source's SQLSTATEs: XQ001 uploader rate, XQ005 network rate. null = rethrow. */
export function reportOutcomeFromSqlError(e: SqlErrorLike): Limited | null {
  if (e.code === "XQ001") return { kind: "limited", reason: "rate", scope: "uploader", retryAfterSeconds: retrySeconds(e) };
  if (e.code === "XQ005") return { kind: "limited", reason: "rate", scope: "network", retryAfterSeconds: retrySeconds(e) };
  return null;
}

// ─────────────────────────────────────────── responses ───────────────────────────────────────────

/**
 * Header diagnostic for the network key: the first write an isolate serves logs WHICH client-address headers were
 * present and how many x-forwarded-for entries there were — names and a count, never values — so the operator can
 * pin DEFINITION_SOURCES_IP_HEADERS. Exported so tests can reset it.
 */
export const ipDiagnostics = { logged: false };

const cors: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": CORS_ALLOW_HEADERS,
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  // Retry-After is not CORS-safelisted: without this a browser client cannot read it on a 429.
  "Access-Control-Expose-Headers": "Retry-After"
};

function reply(status: number, body: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json", ...extra } });
}

function fail(status: number, error: string, extra: Record<string, unknown> = {}): Response {
  return reply(status, { error, ...extra });
}

function refusal(r: Exclude<Parsed<unknown>, { ok: true }>): Response {
  return fail(r.status, r.error, r.fields);
}

const paused = (what: string) => fail(503, "paused", { message: `${what} is paused` });

function limitedReply(r: Limited, cfg: HandlerConfig, report: boolean): Response {
  const retryAfterSeconds = Math.max(1, Math.ceil(r.retryAfterSeconds));
  const headers = { "Retry-After": String(retryAfterSeconds) };
  const net = r.scope === "network";
  if (r.reason === "rate") {
    const limit = report
      ? (net ? cfg.netReportRateLimitPerWindow : cfg.reportRateLimitPerWindow)
      : (net ? cfg.netRateLimitPerWindow : cfg.rateLimitPerWindow);
    const windowSeconds = report ? cfg.reportWindowSeconds : cfg.rateWindowSeconds;
    return reply(429, { error: "rate-limited", scope: r.scope, limit, windowSeconds, retryAfterSeconds }, headers);
  }
  return reply(429, {
    error: "quota-exceeded",
    scope: r.scope,
    quotaBytes: net ? cfg.netQuotaBytes : cfg.quotaBytes,
    windowSeconds: cfg.quotaWindowSeconds,
    retryAfterSeconds
  }, headers);
}

// ─────────────────────────────────────────── routing ───────────────────────────────────────────

type Route = { name: "list" } | { name: "source"; id: string } | { name: "withdraw" | "mine" | "report" } | { name: "unknown" };

/** The path below the function name (`/functions/v1/definition-sources/…` arrives as `/definition-sources/…`). */
function routeOf(url: URL): Route {
  const parts = url.pathname.split("/").filter(Boolean);
  const at = parts.lastIndexOf("definition-sources");
  const rest = at >= 0 ? parts.slice(at + 1) : parts;
  if (rest.length === 0) {
    const action = url.searchParams.get("action");
    if (action === null) return { name: "list" };
    return action === "withdraw" || action === "mine" || action === "report" ? { name: action } : { name: "unknown" };
  }
  if (rest.length === 1 && (rest[0] === "withdraw" || rest[0] === "mine" || rest[0] === "report")) return { name: rest[0] };
  if (rest.length === 2 && rest[0] === "source") return { name: "source", id: rest[1] };
  return { name: "unknown" };
}

/** Writes are open when switched on AND a strong enough network-key secret is configured (fail closed). */
function writesOpen(cfg: HandlerConfig): boolean {
  return cfg.mode === "on" && typeof cfg.ipSalt === "string" && cfg.ipSalt.length >= MIN_IP_SALT_LENGTH;
}

type User = { id: string };

/**
 * Authenticates BEFORE any body is read. `writing` = contribute/report: only those are subject to the anonymous
 * switch — withdraw and /mine stay open to every uploader, so switching anonymous sharing off never strands an
 * earlier anonymous contribution (withdrawal is an erasure path).
 */
async function authorize(req: Request, deps: Deps, cfg: HandlerConfig, writing: boolean): Promise<{ user: User } | { res: Response }> {
  const token = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "")?.[1];
  if (!token || !looksLikeJwt(token)) return { res: fail(401, "unauthorized") };
  const user = await deps.authenticate(token);
  if (user === "unavailable") {
    return {
      res: reply(503, {
        error: "auth-unavailable",
        message: "sign-in could not be checked right now; please try again",
        retryAfterSeconds: AUTH_RETRY_AFTER_SECONDS
      }, { "Retry-After": String(AUTH_RETRY_AFTER_SECONDS) })
    };
  }
  if (!user) return { res: fail(401, "unauthorized") };
  if (writing && user.isAnonymous && !cfg.allowAnonymous) {
    return { res: fail(403, "account-required", { message: "sharing definitions currently needs a signed-in account" }) };
  }
  return { user: { id: user.id } };
}

/** Reads the JSON request body with a hard cap. */
async function readJson(req: Request, limit: number): Promise<{ body: unknown } | { res: Response }> {
  const declared = Number(req.headers.get("content-length"));
  if (req.headers.has("content-length") && Number.isFinite(declared) && declared > limit) {
    return { res: fail(413, "too-large", { limit, bytes: declared }) };
  }
  const raw = await readBodyCapped(req.body, limit);
  if (!(raw instanceof Uint8Array)) return { res: fail(413, "too-large", { limit, bytes: raw.over }) };
  if (raw.length === 0) return { res: fail(400, "empty-body", { message: "request body is empty" }) };
  try {
    return { body: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)) };
  } catch {
    return { res: fail(400, "invalid-json", { message: "request body is not valid UTF-8 JSON" }) };
  }
}

/** The keyed hash of the caller's network (logs header NAMES once per isolate, never an address). */
async function callerNetworkKey(req: Request, cfg: HandlerConfig): Promise<string> {
  if (!ipDiagnostics.logged) {
    ipDiagnostics.logged = true;
    const d = describeClientHeaders(req.headers, cfg.ipHeaders);
    cfg.log("info", `definition-sources: client-address headers present: [${d.present.join(", ")}]; x-forwarded-for entries: ${d.xffEntries}; consulted in order: [${cfg.ipHeaders.join(", ")}]`);
  }
  const network = clientNetwork(req.headers, cfg.ipHeaders);
  if (network === "unknown") {
    const d = describeClientHeaders(req.headers, cfg.ipHeaders);
    cfg.log("warn", `definition-sources: no usable client address (headers present: [${d.present.join(", ")}]); this request is limited in the shared "unknown" network bucket`);
  }
  return await networkKey(cfg.ipSalt!, network, NETWORK_DOMAIN);
}

export async function handleRequest(req: Request, deps: Deps, cfg: HandlerConfig = DEFAULT_CONFIG): Promise<Response> {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const route = routeOf(new URL(req.url));
    if (route.name === "unknown") return fail(404, "not-found");

    if (req.method === "GET") {
      if (route.name === "mine") return await listMine(req, deps, cfg);
      if (route.name === "list" || route.name === "source") {
        if (cfg.mode === "off") return paused("the shared definitions store");
        return route.name === "list" ? await list(new URL(req.url), deps, cfg) : await getSource(route.id, deps);
      }
      return reply(405, { error: "method-not-allowed" }, { Allow: "POST, OPTIONS" });
    }
    if (req.method !== "POST") return reply(405, { error: "method-not-allowed" }, { Allow: "GET, POST, OPTIONS" });

    if (route.name === "withdraw") return await withdraw(req, deps, cfg);
    if (route.name === "list") return await contribute(req, deps, cfg);
    if (route.name === "report") return await report(req, deps, cfg);
    return reply(405, { error: "method-not-allowed" }, { Allow: "GET, OPTIONS" });
  } catch (e) {
    // Details go to the function log (maintainer-only), never to the client. Never log addresses or bodies.
    console.error("definition-sources:", e instanceof Error ? e.message : e);
    return fail(500, "internal", { message: "request failed; please try again later" });
  }
}

// ── GET: the public listing ──

async function list(url: URL, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const q = parseListQuery(url.searchParams);
  if (!q.ok) return refusal(q);
  const { model, firmware, rawFormat } = q.value;
  const rows = cfg.contributeModels.includes(model) ? await deps.selectSources(model, firmware, rawFormat) : [];
  const alternatives: Record<string, number> = {};
  for (const k of SHARED_KINDS) alternatives[k] = 0;
  const sources = [];
  for (const r of rows) {
    if (r.tier === "rejected") continue; // never served (the SQL already excludes it)
    alternatives[r.kind] = r.alternatives;
    sources.push({
      id: r.id,
      kind: r.kind,
      rawFormat: r.rawFormat,
      factHash: r.factHash,
      tier: r.tier,
      quality: r.quality,
      contributors: r.contributors,
      networks: r.networks,
      spotChecks: { passed: r.spotPasses, failed: r.spotFailures },
      firstSeen: r.firstSeenDay,
      lastConfirmedAt: r.lastConfirmedDay,
      bytes: r.bytes,
      summary: r.summary
    });
  }
  // `allowAnonymous` is the very switch authorize() enforces on contribute/report: advertised here so a client can
  // tell, before it mints an anonymous Auth user, that sharing would only be answered with 403 account-required.
  // Appended last: additive, the existing fields keep their names and order. The listing is cached for
  // LIST_MAX_AGE_SECONDS, so a flip of the setting reaches clients within that window.
  return reply(200, { model, firmware, sources, alternatives, allowAnonymous: cfg.allowAnonymous }, { "Cache-Control": `public, max-age=${LIST_MAX_AGE_SECONDS}` });
}

// ── GET /source/<id> ──

/** The public RLS policy's condition. The service role bypasses RLS, so the handler applies it itself. */
export function isServable(r: Pick<SourceRow, "tier" | "quarantined" | "pinned" | "contributors">): boolean {
  return r.tier !== "rejected" && !r.quarantined && (r.pinned || r.contributors > 0);
}

async function getSource(rawId: string, deps: Deps): Promise<Response> {
  const id = parseRowId(rawId);
  if (!id) return fail(400, "invalid-request", { message: "the source id must be a UUID" });
  const row = await deps.getSource(id);
  if (!row || !isServable(row)) return fail(404, "not-found");
  return reply(200, {
    id: row.id,
    model: row.model,
    firmware: row.firmware,
    kind: row.kind,
    rawFormat: row.rawFormat,
    factHash: row.factHash,
    tier: row.tier,
    quality: row.quality,
    summary: row.summary,
    source: row.source
  }, { "Cache-Control": `public, max-age=${SOURCE_MAX_AGE_SECONDS}` });
}

// ── GET /mine ──

async function listMine(req: Request, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const auth = await authorize(req, deps, cfg, false);
  if ("res" in auth) return auth.res;
  const contributions = await deps.listMine(auth.user.id, MINE_LIMIT);
  return reply(200, { contributions: contributions.slice(0, MINE_LIMIT) }, { "Cache-Control": "private, no-store" });
}

// ── POST: contribute ──

async function contribute(req: Request, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  if (!writesOpen(cfg)) return paused("sharing definitions");
  const auth = await authorize(req, deps, cfg, true);
  if ("res" in auth) return auth.res;
  const body = await readJson(req, cfg.maxContributionBytes);
  if ("res" in body) return body.res;

  const parsed = parseContribution(body.body, cfg.now(), { contributeModels: cfg.contributeModels, ...cfg.validation });
  if (!parsed.ok) return refusal(parsed);
  const c: Contribution = parsed.value;

  let facts;
  try {
    facts = await computeFacts(c.source, { model: c.model, firmware: c.firmware, rawFormat: c.rawFormat });
  } catch (e) {
    // The validator is stricter than the fact document's own checks; reaching this is a validator gap. The
    // messages name a field and a rule, never a value.
    if (e instanceof TypeError || e instanceof RangeError) {
      return fail(422, "invalid-source", { path: "source", reason: e.message });
    }
    throw e;
  }
  // Sanitizing can lengthen the text a little (number spellings): the stored form is what counts.
  if (facts.bytes > cfg.maxContributionBytes) return fail(413, "too-large", { limit: cfg.maxContributionBytes, bytes: facts.bytes });

  const key = await callerNetworkKey(req, cfg);
  const r = await deps.contribute({
    userId: auth.user.id,
    networkKey: key,
    model: c.model,
    firmware: c.firmware,
    kind: c.kind,
    rawFormat: c.rawFormat,
    factHash: facts.factHash,
    source: c.source as unknown as Record<string, unknown>,
    summary: facts.summary,
    quality: facts.quality,
    coverageScore: facts.coverageScore,
    bytes: facts.bytes,
    app: c.app,
    consentAt: c.consentAt,
    consentVersion: c.consentVersion,
    maxPerWindow: cfg.rateLimitPerWindow,
    windowSeconds: cfg.rateWindowSeconds,
    netMaxPerWindow: cfg.netRateLimitPerWindow,
    quotaBytes: cfg.quotaBytes,
    quotaWindowSeconds: cfg.quotaWindowSeconds,
    netQuotaBytes: cfg.netQuotaBytes
  });
  if (r.kind === "limited") return limitedReply(r, cfg, false);
  if (r.kind === "rejected") {
    return fail(409, "rejected", { message: "these definitions were reviewed and are not accepted", factHash: facts.factHash });
  }
  return reply(r.created ? 201 : 200, {
    sourceId: r.sourceId,
    factHash: facts.factHash,
    created: r.created,
    deduped: r.deduped,
    confirmed: r.confirmed,
    tier: r.tier,
    contributors: r.contributors,
    networks: r.networks
  });
}

// ── POST /withdraw ──

async function withdraw(req: Request, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  const auth = await authorize(req, deps, cfg, false);
  if ("res" in auth) return auth.res;
  const body = await readJson(req, cfg.maxJsonBodyBytes);
  if ("res" in body) return body.res;
  const parsed = parseWithdrawRequest(body.body);
  if (!parsed.ok) return refusal(parsed);
  const w: WithdrawRequest = parsed.value;
  const one = "sourceId" in w;
  const r = await deps.withdraw({
    userId: auth.user.id,
    sourceId: one ? w.sourceId : null,
    model: one ? null : w.model,
    firmware: one ? null : w.firmware
  });
  // Unknown, foreign, or unlinked (after 180 days): nothing of the caller's matched.
  if (one && r.withdrawn === 0) return fail(404, "not-found");
  return reply(200, { withdrawn: r.withdrawn, deletedSources: r.deletedSources });
}

// ── POST /report ──

async function report(req: Request, deps: Deps, cfg: HandlerConfig): Promise<Response> {
  if (!writesOpen(cfg)) return paused("reporting");
  const auth = await authorize(req, deps, cfg, true);
  if ("res" in auth) return auth.res;
  const body = await readJson(req, cfg.maxJsonBodyBytes);
  if ("res" in body) return body.res;
  const parsed = parseReportRequest(body.body);
  if (!parsed.ok) return refusal(parsed);
  const p = parsed.value;
  const key = await callerNetworkKey(req, cfg);
  const r = await deps.report({
    userId: auth.user.id,
    networkKey: key,
    sourceId: p.sourceId,
    verdict: p.verdict,
    checked: p.checked,
    answered: p.answered,
    mismatches: p.mismatches,
    app: p.app,
    maxPerWindow: cfg.reportRateLimitPerWindow,
    netMaxPerWindow: cfg.netReportRateLimitPerWindow,
    windowSeconds: cfg.reportWindowSeconds
  });
  if (r.kind === "not-found") return fail(404, "not-found");
  if (r.kind === "limited") return limitedReply(r, cfg, true);
  return reply(200, { ok: true, quarantined: r.quarantined });
}
