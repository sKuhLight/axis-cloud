// Unit tests for the shared CORS headers. Run with:
//   deno test supabase/functions/_shared/
// No Supabase stack or network is needed. The device-profiles and delete-account index.ts files call
// Deno.serve on import, so they cannot be imported here; they build their headers with corsHeaders(), which
// is what these tests pin.
import { assert, assertEquals } from "jsr:@std/assert@1";
import { type Deps, handleRequest } from "../diagnostic-captures/handler.ts";
import { type Deps as EditorCacheDeps, handleRequest as handleEditorCacheRequest } from "../editor-caches/handler.ts";
import { CORS_ALLOW_HEADERS, corsHeaders } from "./cors.ts";

function allowed(list: string): string[] {
  return list.split(",").map((h) => h.trim().toLowerCase());
}

Deno.test("allows every request header a supabase-js browser client sends", () => {
  const allow = allowed(corsHeaders("GET, POST, OPTIONS")["Access-Control-Allow-Headers"]);
  for (const h of ["authorization", "content-type", "apikey", "x-client-info"]) {
    assert(allow.includes(h), `Access-Control-Allow-Headers is missing ${h}`);
  }
});

Deno.test("allows any origin and echoes the methods it is given", () => {
  const h = corsHeaders("POST, OPTIONS");
  assertEquals(h["Access-Control-Allow-Origin"], "*");
  assertEquals(h["Access-Control-Allow-Methods"], "POST, OPTIONS");
  assertEquals(h["Access-Control-Allow-Headers"], CORS_ALLOW_HEADERS);
});

Deno.test("matches the Allow-Headers of diagnostic-captures, so the functions cannot drift apart", async () => {
  // OPTIONS is answered before the handler touches its dependencies.
  const res = await handleRequest(new Request("http://localhost/x", { method: "OPTIONS" }), {} as Deps);
  assertEquals(allowed(res.headers.get("access-control-allow-headers")!), allowed(CORS_ALLOW_HEADERS));
});

Deno.test("matches the Allow-Headers of editor-caches, so the functions cannot drift apart", async () => {
  // OPTIONS is answered before the handler touches its dependencies.
  const res = await handleEditorCacheRequest(new Request("http://localhost/x", { method: "OPTIONS" }), {} as EditorCacheDeps);
  assertEquals(allowed(res.headers.get("access-control-allow-headers")!), allowed(CORS_ALLOW_HEADERS));
});
