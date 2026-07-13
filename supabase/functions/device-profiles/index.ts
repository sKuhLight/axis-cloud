import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

// Global device-definition profile store (AXISCLOUD-2). Profiles are derived `BuiltCache` docs
// (ForgeFX deviceCache.ts → forgefx-midi buildCache), identical for every device of the same model on
// the same firmware — NOT user data. First user on a new firmware uploads; everyone else downloads.
//
//   GET  ?model=<int>&firmware=<string>  → newest matching profile + metadata (404 if none). Public.
//   POST { model, firmware, source, profile }  → validate + hash server-side + insert. Requires a JWT.
//
// verify_jwt is OFF for this function (config.toml) so GET stays public; POST verifies the caller's
// token manually. Writes use the service role — the table has no client-facing write policy.

// Reject bodies larger than this before parsing (a BuiltCache is well under a MB; this bounds abuse).
const MAX_BODY_BYTES = 6 * 1024 * 1024;
// Per-user insert budget: at most this many NEW profiles per rolling hour (dedups don't count against it).
const RATE_LIMIT_PER_HOUR = 10;

const cors: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS"
};
const json = { ...cors, "Content-Type": "application/json" };

/** sha256 hex of a string (server-computed — a client-supplied hash is never trusted). */
async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Canonical JSON: objects with sorted keys, recursively. Hashing this makes dedup independent of the
 *  key order a client happened to serialize with — identical content always lands on the same row. */
function canonicalJson(v: unknown): string {
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
function validateProfile(p: unknown): string | null {
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

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });

  const url = Deno.env.get("SUPABASE_URL")!;
  const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const admin = createClient(url, service, { auth: { persistSession: false } });

  // ── GET: newest profile for (model, firmware). Public, cacheable. ──
  if (req.method === "GET") {
    const q = new URL(req.url).searchParams;
    const model = Number(q.get("model"));
    const firmware = q.get("firmware") ?? "";
    if (!Number.isInteger(model) || model < 1 || model > 255 || !firmware) {
      return new Response(JSON.stringify({ error: "bad request: model (1..255) and firmware required" }), { status: 400, headers: json });
    }
    const { data, error } = await admin
      .from("device_profiles")
      .select("id, model, firmware, content_hash, profile, source, record_count, created_at")
      .eq("model", model)
      .eq("firmware", firmware)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    if (error) return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: json });
    if (!data) return new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: json });
    return new Response(JSON.stringify(data), { headers: { ...json, "Cache-Control": "public, max-age=300" } });
  }

  // ── POST: upload a profile. Requires a valid user JWT. ──
  if (req.method === "POST") {
    const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
    const authHeader = req.headers.get("Authorization") ?? "";
    const userClient = createClient(url, anon, { global: { headers: { Authorization: authHeader } } });
    const { data: { user }, error: uerr } = await userClient.auth.getUser();
    if (uerr || !user) return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: json });

    // Cheap pre-parse size guard (Content-Length is advisory but bounds the common case).
    const len = Number(req.headers.get("Content-Length") ?? 0);
    if (len && len > MAX_BODY_BYTES) return new Response(JSON.stringify({ error: "payload too large" }), { status: 413, headers: json });

    const raw = await req.text();
    if (raw.length > MAX_BODY_BYTES) return new Response(JSON.stringify({ error: "payload too large" }), { status: 413, headers: json });
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(raw);
    } catch {
      return new Response(JSON.stringify({ error: "invalid JSON" }), { status: 400, headers: json });
    }

    const model = body.model;
    const firmware = body.firmware;
    const source = body.source;
    const profile = body.profile;

    if (typeof model !== "number" || !Number.isInteger(model) || model < 1 || model > 255) {
      return new Response(JSON.stringify({ error: "model must be an integer 1..255" }), { status: 400, headers: json });
    }
    if (typeof firmware !== "string" || !/^\d+\.\d+/.test(firmware)) {
      return new Response(JSON.stringify({ error: "firmware must match \\d+\\.\\d+" }), { status: 400, headers: json });
    }
    if (source !== "live-walk" && source !== "editor-cache") {
      return new Response(JSON.stringify({ error: "source must be 'live-walk' or 'editor-cache'" }), { status: 400, headers: json });
    }
    const bad = validateProfile(profile);
    if (bad) return new Response(JSON.stringify({ error: bad }), { status: 400, headers: json });
    // The API source kind must agree with what the profile says built it: live-walk ↔ codec 'live',
    // editor-cache ↔ codec 'bytes'. Prevents mislabeled rows in the shared store.
    const metaSource = ((profile as Record<string, unknown>).meta as Record<string, unknown>).source;
    const expected = source === "live-walk" ? "live" : "bytes";
    if (metaSource !== expected) {
      return new Response(JSON.stringify({ error: `source '${source}' does not match profile.meta.source '${metaSource}'` }), { status: 400, headers: json });
    }

    // Rate limit: reject if this user already inserted > N profiles in the last hour.
    const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const { count, error: cerr } = await admin
      .from("device_profiles")
      .select("id", { count: "exact", head: true })
      .eq("created_by", user.id)
      .gte("created_at", since);
    if (cerr) return new Response(JSON.stringify({ error: cerr.message }), { status: 500, headers: json });
    if ((count ?? 0) >= RATE_LIMIT_PER_HOUR) {
      return new Response(JSON.stringify({ error: "rate limited" }), { status: 429, headers: json });
    }

    // Hash the canonical (sorted-key) profile JSON server-side — never trust a client hash.
    const contentHash = await sha256Hex(canonicalJson(profile));
    const recordCount = (profile as { meta?: { recordCount?: unknown } }).meta?.recordCount;

    const { data, error } = await admin
      .from("device_profiles")
      .insert({
        model,
        firmware,
        content_hash: contentHash,
        profile,
        source,
        record_count: typeof recordCount === "number" ? recordCount : null,
        created_by: user.id
      })
      .select("id, model, firmware, content_hash, source, created_at")
      .single();

    if (error) {
      // 23505 = unique_violation → an identical (model, firmware, content) profile already exists.
      if ((error as { code?: string }).code === "23505") {
        return new Response(JSON.stringify({ deduped: true, contentHash }), { headers: json });
      }
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: json });
    }
    return new Response(JSON.stringify({ ok: true, ...data }), { status: 201, headers: json });
  }

  return new Response("method not allowed", { status: 405, headers: cors });
});
