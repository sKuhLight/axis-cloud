// Unit tests for the shared network key (_shared/network.ts). Run with:
//   deno test supabase/functions/_shared/
// The address parsing itself is covered by editor-caches/validate.test.ts (it imports the same functions through
// the editor-caches re-export); these tests pin what the move must not change and the per-store separation.
import { assertEquals, assertMatch, assertNotEquals } from "jsr:@std/assert@1";
import { NETWORK_DOMAIN as DEFINITION_SOURCE_DOMAIN } from "../definition-sources/validate.ts";
import { EDITOR_CACHE_NETWORK_DOMAIN, networkKey as editorCacheNetworkKey } from "../editor-caches/validate.ts";
import { clientNetwork, DEFAULT_IP_HEADERS, networkKey, parseHeaderList } from "./network.ts";

const SALT = "test-salt-0123456789abcdef0123456789abcdef";

/** HMAC-SHA256(secret, message) as hex, computed independently of network.ts. */
async function hmac(secret: string, message: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(message))), (b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.test("the editor-cache key is unchanged by the move (stored keys and limits keep working)", async () => {
  assertEquals(EDITOR_CACHE_NETWORK_DOMAIN, "editor-cache-network:v1");
  assertEquals(await editorCacheNetworkKey(SALT, "v4:203.0.113.7"), await hmac(SALT, "editor-cache-network:v1:v4:203.0.113.7"));
});

Deno.test("each store has its own domain: the same network and secret give unrelated keys", async () => {
  assertEquals(DEFINITION_SOURCE_DOMAIN, "definition-source-network:v1");
  const a = await networkKey(SALT, "v4:203.0.113.7", EDITOR_CACHE_NETWORK_DOMAIN);
  const b = await networkKey(SALT, "v4:203.0.113.7", DEFINITION_SOURCE_DOMAIN);
  assertMatch(b, /^[0-9a-f]{64}$/);
  assertNotEquals(a, b);
  assertEquals(b, await hmac(SALT, "definition-source-network:v1:v4:203.0.113.7"));
});

Deno.test("parseHeaderList: trimmed, lower-cased, defaults when empty", () => {
  assertEquals(parseHeaderList(" CF-Connecting-IP , x-real-ip,,"), ["cf-connecting-ip", "x-real-ip"]);
  assertEquals(parseHeaderList(""), DEFAULT_IP_HEADERS);
  assertEquals(parseHeaderList(undefined), DEFAULT_IP_HEADERS);
  // a pinned header is the only one consulted
  const h = new Headers({ "cf-connecting-ip": "203.0.113.7", "x-real-ip": "198.51.100.1" });
  assertEquals(clientNetwork(h, parseHeaderList("x-real-ip")), "v4:198.51.100.1");
});
