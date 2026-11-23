// The PostgREST request the store adapter (index.ts selectBestProfile) sends, built by the REAL supabase-js query
// builder through handler.ts applyProfileFilter — with a fake fetch, so no network, no stack, no secrets. handler.test.ts
// covers what GET does with the answer; this pins what reaches PostgREST, above all the ranking's `order=` parameter.
import { assertEquals } from "jsr:@std/assert@1";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { applyProfileFilter, LEGACY_SCHEMAS, PROFILE_ORDER, type ProfileFilter, RESPONSE_COLUMNS } from "./handler.ts";

/** Run the adapter's query (same calls as index.ts) and return the URL it requested. */
async function requestedUrl(f: ProfileFilter): Promise<URL> {
  const urls: URL[] = [];
  const fakeFetch = ((input: Request | URL | string, init?: RequestInit) => {
    urls.push(new URL(new Request(input, init).url));
    return Promise.resolve(new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } }));
  }) as typeof fetch;
  const admin = createClient("http://127.0.0.1:1", "test-key", {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { fetch: fakeFetch }
  });
  // the same two statements as index.ts selectBestProfile
  const query = applyProfileFilter(admin.from("device_profiles").select(RESPONSE_COLUMNS.join(", ")), f);
  const { data, error } = await query.limit(1).maybeSingle();
  assertEquals(error, null);
  assertEquals(data, null);
  assertEquals(urls.length, 1);
  return urls[0];
}

const base = { model: 17, firmware: "13.0", legacySchemas: LEGACY_SCHEMAS, order: PROFILE_ORDER };

Deno.test("PROFILE_ORDER reaches PostgREST as order=source.asc.nullslast,row_count.desc.nullslast,created_at.asc.nullslast", async () => {
  const u = await requestedUrl({ ...base, schema: 2 });
  assertEquals(u.pathname, "/rest/v1/device_profiles");
  assertEquals(u.searchParams.get("order"), "source.asc.nullslast,row_count.desc.nullslast,created_at.asc.nullslast");
  assertEquals(u.searchParams.get("limit"), "1");
});

Deno.test("the adapter asks for the v1 columns of the candidates of (model, firmware, schema)", async () => {
  const u = await requestedUrl({ ...base, schema: 2 });
  assertEquals(u.searchParams.get("select"), RESPONSE_COLUMNS.join(","));
  assertEquals(u.searchParams.get("model"), "eq.17");
  assertEquals(u.searchParams.get("firmware"), "eq.13.0");
  assertEquals(u.searchParams.get("profile->meta->>schema"), "eq.2");
  assertEquals(u.searchParams.get("or"), null);
});

Deno.test("without a schema the adapter asks for unstamped rows and the legacy schemas, ranked the same way", async () => {
  const u = await requestedUrl({ ...base, schema: null });
  assertEquals(u.searchParams.get("profile->meta->>schema"), null);
  assertEquals(u.searchParams.get("or"), "(profile->meta->>schema.is.null,profile->meta->>schema.in.(0,1))");
  assertEquals(u.searchParams.get("order"), "source.asc.nullslast,row_count.desc.nullslast,created_at.asc.nullslast");
});
