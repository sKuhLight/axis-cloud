import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  applyProfileFilter,
  type Deps,
  handleRequest,
  type InsertedProfile,
  type InsertResult,
  type NewProfile,
  type ProfileFilter,
  type ProfileRow,
  RESPONSE_COLUMNS
} from "./handler.ts";

// Global device-definition profile store (AXISCLOUD-2), v1. Request/response contract, validation and the RANKING of
// stored profiles: handler.ts. The `row_count` the ranking uses is computed by the database
// (migrations/20261201130000_device_profiles_ranking.sql — DEPLOY THAT MIGRATION BEFORE THIS FUNCTION: GET orders by
// the new column). This file only wires the Supabase clients.
//
// verify_jwt is OFF for this function (config.toml) so GET stays public; POST verifies the caller's token
// manually. Writes use the service role — the table has no client-facing write policy.

const url = Deno.env.get("SUPABASE_URL")!;
const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const admin = createClient(url, service, { auth: { persistSession: false, autoRefreshToken: false } });

const deps: Deps = {
  async authenticate(authorization) {
    // The caller's own token goes along as the Authorization header of a client built for this request; the Auth
    // server then answers who it belongs to (unchanged since v1 went live).
    const userClient = createClient(url, anon, { global: { headers: { Authorization: authorization } } });
    const { data: { user }, error } = await userClient.auth.getUser();
    if (error || !user) return null;
    return { id: user.id, isAnonymous: user.is_anonymous === true };
  },

  async selectBestProfile(f: ProfileFilter) {
    // Candidates + the ranking (handler.ts PROFILE_ORDER) as PostgREST
    // `order=source.asc.nullslast,row_count.desc.nullslast,created_at.asc.nullslast` (pinned by query.test.ts).
    const query = applyProfileFilter(admin.from("device_profiles").select(RESPONSE_COLUMNS.join(", ")), f);
    const { data, error } = await query.limit(1).maybeSingle();
    if (error) throw new Error(error.message);
    return (data as unknown as ProfileRow | null) ?? null;
  },

  async countRecentInserts(userId, sinceIso) {
    const { count, error } = await admin
      .from("device_profiles")
      .select("id", { count: "exact", head: true })
      .eq("created_by", userId)
      .gte("created_at", sinceIso);
    if (error) throw new Error(error.message);
    return count ?? 0;
  },

  async insertProfile(row: NewProfile): Promise<InsertResult> {
    const { data, error } = await admin
      .from("device_profiles")
      .insert(row)
      .select("id, model, firmware, content_hash, source, created_at")
      .single();
    if (error) {
      // 23505 = unique_violation → an identical (model, firmware, content) profile already exists.
      if ((error as { code?: string }).code === "23505") return { kind: "duplicate" };
      throw new Error(error.message);
    }
    return { kind: "inserted", row: data as InsertedProfile };
  }
};

Deno.serve((req: Request) => handleRequest(req, deps));
