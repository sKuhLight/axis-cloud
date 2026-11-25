// The client NETWORK of a request and its keyed hash, shared by the functions that limit per network
// (editor-caches, definition-sources). Web-standard APIs only (no Deno globals), so it is unit-testable without a
// Supabase stack. Not a function itself: the Supabase CLI skips directories that start with an underscore.
//
// A network only ever leaves a function as HMAC-SHA256(secret, "<domain>:<network>"): never the address. Each store
// uses its OWN secret and its own domain string, so the keys of two stores cannot be matched against each other.

/** Default request headers the client address is taken from, in order (see clientNetwork). */
export const DEFAULT_IP_HEADERS: readonly string[] = ["cf-connecting-ip", "x-real-ip", "x-forwarded-for"];

function parseIPv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p <= 255) ? parts : null;
}

/** The eight 16-bit groups of an IPv6 address (with `::` and an embedded IPv4 tail); null if not one. */
function parseIPv6(s: string): number[] | null {
  let str = s.toLowerCase();
  const zone = str.indexOf("%");
  if (zone >= 0) str = str.slice(0, zone);
  let tail: number[] = [];
  const lastColon = str.lastIndexOf(":");
  if (lastColon >= 0 && str.slice(lastColon + 1).includes(".")) {
    const v4 = parseIPv4(str.slice(lastColon + 1));
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    str = str.slice(0, lastColon + 1) + "0:0"; // two placeholder groups (an IPv4 tail fills two), replaced below
  }
  const halves = str.split("::");
  if (halves.length > 2) return null;
  const group = (g: string) => (/^[0-9a-f]{1,4}$/.test(g) ? Number.parseInt(g, 16) : NaN);
  const left = halves[0] ? halves[0].split(":").map(group) : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":").map(group) : [];
  if ([...left, ...right].some((n) => Number.isNaN(n))) return null;
  let groups: number[];
  if (halves.length === 2) {
    const fill = 8 - left.length - right.length;
    if (fill < 1) return null;
    groups = [...left, ...new Array(fill).fill(0), ...right];
  } else {
    groups = left;
  }
  if (groups.length !== 8) return null;
  if (tail.length) groups = [...groups.slice(0, 6), ...tail];
  return groups;
}

/**
 * The client's NETWORK as a canonical string, used only as HMAC input (never stored or logged):
 * `v4:<a.b.c.d>` for IPv4 (incl. IPv4-mapped IPv6), `v6:<first four groups>` for IPv6 (a /64 is what one
 * subscriber typically gets, so the limits cannot be dodged by rotating the interface id), `unknown` when no
 * header carries a parseable address (all such requests then share one bucket — fail closed, not open).
 *
 * Header trust: `headers` lists the headers to consult, in order. The defaults fit the hosted platform:
 * `cf-connecting-ip` is set by the edge proxy (a client-sent value is overwritten), `x-real-ip` by the API
 * gateway, and of `x-forwarded-for` only the LAST entry is used — the one the nearest proxy appended; earlier
 * entries are whatever the client sent. A self-hosted deployment behind a different proxy can override the list
 * (EDITOR_CACHE_IP_HEADERS / DEFINITION_SOURCES_IP_HEADERS) with the header its proxy sets.
 */
export function clientNetwork(headers: Headers, headerOrder: readonly string[] = DEFAULT_IP_HEADERS): string {
  for (const name of headerOrder) {
    const raw = headers.get(name);
    if (!raw) continue;
    const entries = raw.split(",").map((e) => e.trim()).filter(Boolean);
    let candidate = name.toLowerCase() === "x-forwarded-for" ? entries[entries.length - 1] : entries[0];
    if (!candidate) continue;
    // "[v6]:port" / "v4:port"
    const bracket = /^\[([^\]]+)\](?::\d+)?$/.exec(candidate);
    if (bracket) candidate = bracket[1];
    else if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(candidate)) candidate = candidate.replace(/:\d+$/, "");
    const v4 = parseIPv4(candidate);
    if (v4) return `v4:${v4.join(".")}`;
    const v6 = parseIPv6(candidate);
    if (v6) {
      // IPv4-mapped (::ffff:a.b.c.d) is an IPv4 client.
      if (v6.slice(0, 5).every((g) => g === 0) && v6[5] === 0xffff) {
        return `v4:${v6[6] >> 8}.${v6[6] & 0xff}.${v6[7] >> 8}.${v6[7] & 0xff}`;
      }
      return `v6:${v6.slice(0, 4).map((g) => g.toString(16)).join(":")}`;
    }
  }
  return "unknown";
}

/**
 * Which of the client-address headers a request carries, and how many entries its x-forwarded-for has — NEVER
 * their values. Logged (sampled) so the operator can confirm on the hosted platform which header the proxy sets
 * and then pin the function's `…_IP_HEADERS` secret to it.
 */
export function describeClientHeaders(headers: Headers, headerOrder: readonly string[] = DEFAULT_IP_HEADERS): { present: string[]; xffEntries: number } {
  const names = [...new Set([...DEFAULT_IP_HEADERS, ...headerOrder].map((h) => h.toLowerCase()))];
  const present = names.filter((h) => (headers.get(h) ?? "").trim() !== "");
  const xff = headers.get("x-forwarded-for") ?? "";
  return { present, xffEntries: xff.split(",").map((e) => e.trim()).filter(Boolean).length };
}

/** A comma-separated header list from a function secret (`a, B ,c` -> `["a", "b", "c"]`); the defaults when empty. */
export function parseHeaderList(raw: string | undefined | null): readonly string[] {
  const list = (raw ?? "").split(",").map((h) => h.trim().toLowerCase()).filter(Boolean);
  return list.length ? list : DEFAULT_IP_HEADERS;
}

/**
 * HMAC-SHA256(secret, `${domain}:${network}`) as lowercase hex — the only form in which a network reaches the
 * database. `domain` names the store and the scheme version (`editor-cache-network:v1`,
 * `definition-source-network:v1`); together with a per-store secret it keeps the stores' keys unrelated.
 */
export async function networkKey(secret: string, network: string, domain: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`${domain}:${network}`));
  return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, "0")).join("");
}
