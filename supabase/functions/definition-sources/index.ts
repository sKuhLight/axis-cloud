import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { parseHeaderList } from "../_shared/network.ts";
import type { FactKind } from "./facts.ts";
import {
  contributeOutcomeFromSqlError,
  isAuthOutage,
  type ContributionSummary,
  DEFAULT_CONFIG,
  type Deps,
  handleRequest,
  type HandlerConfig,
  type ListedSourceRow,
  type Mode,
  reportOutcomeFromSqlError,
  type SourceRow,
  type Tier
} from "./handler.ts";
import { MIN_IP_SALT_LENGTH, resolveIpSalt } from "./validate.ts";

// Shared device definitions (cloud v2). Request/response contract, error codes, availability: handler.ts.
// Validation and sanitizing: validate.ts. Fact hash, summary, quality: facts.ts. Ranking, tiers, limits, dedupe:
// the SQL functions of migrations/20261201120000_definition_sources.sql. This file only wires the Supabase clients
// and reads the configuration.
//
// verify_jwt is OFF (config.toml): the listing and the source bodies are public, and the handler authenticates
// every other request itself before it reads anything. Everything runs with the service role — which BYPASSES RLS,
// so the source read below filters servable rows itself and selects only the public columns (never the precise
// first_seen / last_confirmed_at, never anything of the private tables except the caller's own rows in /mine).
//
// Function secrets (`supabase secrets set …` on a hosted project; an env file for `functions serve` locally):
//   DEFINITION_SOURCES_IP_SALT        REQUIRED for writes, ≥ 32 characters (e.g. 64 random hex), and NOT the
//                                     editor-cache salt (the two stores' network keys must not be comparable).
//                                     Missing, shorter, or equal to EDITOR_CACHE_IP_SALT: contribute/report 503
//                                     paused (reads, withdraw, /mine work); the reason is logged at start-up.
//                                     Rotating it resets the per-network counters.
//   DEFINITION_SOURCES                `on` (default) | `readonly` (no contribute/report) | `off` (no public reads
//                                     either). Withdraw and /mine work in every mode. Any other value = readonly.
//   DEFINITION_SOURCES_ALLOW_ANONYMOUS  `0`/`false`/`off` = refuse anonymous sessions for contribute/report
//                                     (403 account-required). Default: allowed.
//   DEFINITION_SOURCES_IP_HEADERS     comma-separated request headers to read the client address from (default
//                                     cf-connecting-ip,x-real-ip,x-forwarded-for — for x-forwarded-for the LAST
//                                     entry). PIN it after a staging check (the first write per isolate logs the
//                                     header NAMES present).

const url = Deno.env.get("SUPABASE_URL")!;
const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });
// Token verification goes through the Auth server with the anon client (explicit jwt, no session state).
const verifier = createClient(url, anon, { auth: { persistSession: false, autoRefreshToken: false } });

const salt = resolveIpSalt(Deno.env.get("DEFINITION_SOURCES_IP_SALT"), Deno.env.get("EDITOR_CACHE_IP_SALT"));
if (salt.problem === "shared") {
  console.error("definition-sources: DEFINITION_SOURCES_IP_SALT equals EDITOR_CACHE_IP_SALT — sharing and reports are paused until it has a value of its own");
} else if (salt.problem) {
  console.error(`definition-sources: DEFINITION_SOURCES_IP_SALT is missing or shorter than ${MIN_IP_SALT_LENGTH} characters — sharing and reports are paused until it is set`);
}
const modeEnv = (Deno.env.get("DEFINITION_SOURCES") ?? "").trim().toLowerCase();
let mode: Mode = "on";
if (modeEnv === "off" || modeEnv === "readonly") mode = modeEnv;
else if (modeEnv !== "" && modeEnv !== "on") {
  console.error("definition-sources: DEFINITION_SOURCES is not on|readonly|off — treating it as readonly");
  mode = "readonly";
}
const allowAnonymousEnv = (Deno.env.get("DEFINITION_SOURCES_ALLOW_ANONYMOUS") ?? "").trim().toLowerCase();

const config: HandlerConfig = {
  ...DEFAULT_CONFIG,
  mode,
  allowAnonymous: !(allowAnonymousEnv === "0" || allowAnonymousEnv === "false" || allowAnonymousEnv === "off"),
  ipSalt: salt.salt,
  ipHeaders: parseHeaderList(Deno.env.get("DEFINITION_SOURCES_IP_HEADERS"))
};

/** The public columns of definition_sources plus what the servability check needs. */
const SOURCE_COLUMNS = "id, model, firmware, kind, raw_format, fact_hash, tier, quality, summary, source, pinned, contributors, quarantined";

const rowsOf = (data: unknown): Record<string, unknown>[] =>
  (Array.isArray(data) ? data : data ? [data] : []) as Record<string, unknown>[];

const deps: Deps = {
  async authenticate(accessToken) {
    try {
      const { data, error } = await verifier.auth.getUser(accessToken);
      if (error) return isAuthOutage(error as { name?: string; status?: number }) ? "unavailable" : null;
      return data.user ? { id: data.user.id, isAnonymous: data.user.is_anonymous === true } : null;
    } catch (e) {
      // supabase-js reports fetch failures as errors; a throw is unexpected and treated as an outage too.
      console.error("definition-sources: token check failed:", e instanceof Error ? e.message : e);
      return "unavailable";
    }
  },

  async selectSources(model, firmware, rawFormatMax) {
    const { data, error } = await admin.rpc("select_definition_sources", {
      p_model: model,
      p_firmware: firmware,
      p_raw_format_max: rawFormatMax
    });
    if (error) throw error;
    return rowsOf(data).map((d): ListedSourceRow => ({
      id: d.id as string,
      kind: d.kind as FactKind,
      rawFormat: d.raw_format as number,
      factHash: d.fact_hash as string,
      tier: d.tier as Tier,
      quality: d.quality as number,
      contributors: d.contributors as number,
      networks: d.networks as number,
      spotPasses: d.spot_passes as number,
      spotFailures: d.spot_failures as number,
      firstSeenDay: d.first_seen_day as string,
      lastConfirmedDay: (d.last_confirmed_day as string | null) ?? null,
      bytes: d.bytes as number,
      summary: (d.summary as Record<string, unknown>) ?? {},
      alternatives: d.alternatives as number
    }));
  },

  async getSource(id) {
    // Service role: RLS does not apply, so the public policy's condition is repeated here (and in the handler).
    const { data, error } = await admin
      .from("definition_sources")
      .select(SOURCE_COLUMNS)
      .eq("id", id)
      .neq("tier", "rejected")
      .eq("quarantined", false)
      .or("pinned.eq.true,contributors.gt.0")
      .maybeSingle();
    if (error) throw error;
    if (!data) return null;
    const d = data as Record<string, unknown>;
    return {
      id: d.id as string,
      model: d.model as number,
      firmware: d.firmware as string,
      kind: d.kind as FactKind,
      rawFormat: d.raw_format as number,
      factHash: d.fact_hash as string,
      tier: d.tier as Tier,
      quality: d.quality as number,
      summary: (d.summary as Record<string, unknown>) ?? {},
      source: d.source as Record<string, unknown>,
      pinned: d.pinned === true,
      contributors: d.contributors as number,
      quarantined: d.quarantined === true
    } satisfies SourceRow;
  },

  async contribute(a) {
    const { data, error } = await admin.rpc("contribute_definition_source", {
      p_user_id: a.userId,
      p_network_key: a.networkKey,
      p_model: a.model,
      p_firmware: a.firmware,
      p_kind: a.kind,
      p_raw_format: a.rawFormat,
      p_fact_hash: a.factHash,
      p_source: a.source,
      p_summary: a.summary,
      p_quality: a.quality,
      p_coverage_score: a.coverageScore,
      p_bytes: a.bytes,
      p_app: a.app,
      p_consent_at: a.consentAt,
      p_consent_version: a.consentVersion,
      p_max_per_window: a.maxPerWindow,
      p_window_seconds: a.windowSeconds,
      p_net_max_per_window: a.netMaxPerWindow,
      p_quota_bytes: a.quotaBytes,
      p_quota_window_seconds: a.quotaWindowSeconds,
      p_net_quota_bytes: a.netQuotaBytes
    });
    if (error) {
      const mapped = contributeOutcomeFromSqlError(error as { code?: string; details?: string });
      if (mapped) return mapped;
      throw error;
    }
    const row = rowsOf(data)[0];
    if (!row) throw new Error("contribute_definition_source returned no row");
    return {
      kind: "ok",
      sourceId: row.source_id as string,
      created: row.created === true,
      deduped: row.deduped === true,
      confirmed: row.confirmed === true,
      tier: row.tier as Tier,
      contributors: row.contributors as number,
      networks: row.networks as number
    };
  },

  async withdraw(a) {
    const { data, error } = await admin.rpc("withdraw_definition_contributions", {
      p_user_id: a.userId,
      p_source_id: a.sourceId,
      p_model: a.model,
      p_firmware: a.firmware
    });
    if (error) throw error;
    const row = rowsOf(data)[0];
    return { withdrawn: (row?.withdrawn as number) ?? 0, deletedSources: (row?.deleted_sources as number) ?? 0 };
  },

  async listMine(userId, limit) {
    // Linked contributions only (an unlinked one has no user id any more). Two plain queries instead of an embed
    // over the composite foreign key.
    const { data, error } = await admin
      .from("definition_source_contributions")
      .select("id, source_id, model, firmware, kind, created_at, linked_until")
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .limit(limit);
    if (error) throw error;
    const rows = rowsOf(data);
    const ids = [...new Set(rows.map((r) => r.source_id as string))];
    const hashes = new Map<string, string>();
    if (ids.length) {
      const { data: src, error: serr } = await admin.from("definition_sources").select("id, fact_hash").in("id", ids);
      if (serr) throw serr;
      for (const s of rowsOf(src)) hashes.set(s.id as string, s.fact_hash as string);
    }
    return rows.map((r): ContributionSummary => ({
      id: r.id as string,
      sourceId: r.source_id as string,
      model: r.model as number,
      firmware: r.firmware as string,
      kind: r.kind as FactKind,
      factHash: hashes.get(r.source_id as string) ?? null,
      createdAt: r.created_at as string,
      linkedUntil: r.linked_until as string
    }));
  },

  async report(a) {
    const { data, error } = await admin.rpc("report_definition_source", {
      p_user_id: a.userId,
      p_network_key: a.networkKey,
      p_source_id: a.sourceId,
      p_verdict: a.verdict,
      p_checked: a.checked,
      p_answered: a.answered,
      p_mismatches: a.mismatches,
      p_app: a.app,
      p_max_per_window: a.maxPerWindow,
      p_net_max_per_window: a.netMaxPerWindow,
      p_window_seconds: a.windowSeconds
    });
    if (error) {
      const mapped = reportOutcomeFromSqlError(error as { code?: string; details?: string });
      if (mapped) return mapped;
      throw error;
    }
    const row = rowsOf(data)[0];
    // No row: the source does not exist (any more).
    return row ? { kind: "ok", quarantined: row.quarantined === true } : { kind: "not-found" };
  }
};

Deno.serve((req: Request) => handleRequest(req, deps, config));
