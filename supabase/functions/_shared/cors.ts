// CORS headers shared by the browser-facing edge functions (device-profiles, delete-account). No
// Deno-specific globals here, so it is unit-testable (cors.test.ts). Not a function itself: the Supabase
// CLI skips directories that start with an underscore when deploying.
//
// Request headers a browser may send: supabase-js (and any fetch that mimics it) adds `apikey` and
// `x-client-info` on top of `authorization` and `content-type`. None of them is CORS-safelisted, so each
// must be listed here or the preflight fails and the browser never sends the real request.
// diagnostic-captures/handler.ts and editor-caches/handler.ts carry the same list; cors.test.ts fails if they
// drift apart.
export const CORS_ALLOW_HEADERS = "authorization, content-type, apikey, x-client-info";

/** CORS response headers for a function; `methods` is the Access-Control-Allow-Methods value. */
export function corsHeaders(methods: string): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": CORS_ALLOW_HEADERS,
    "Access-Control-Allow-Methods": methods
  };
}
