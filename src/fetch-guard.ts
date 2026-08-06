import { isIP } from 'node:net';
import { lookup } from 'node:dns/promises';

/**
 * Guards for fetches whose URL came from scanned page content rather than from
 * the user.
 *
 * peep's whole job is pointing itself at domains it does not trust, and a
 * scanned page controls its own `<link rel="icon">`, `<link rel="stylesheet">`
 * and `<script src>` values. Without a guard, a hostile page can aim peep's
 * process at anything its network can reach — the classic target being a cloud
 * metadata endpoint (`169.254.169.254`) whose response would then be hashed
 * into a scan result.
 *
 * The trust boundary is deliberately drawn at *who chose the URL*:
 *
 * - The scan target itself is trusted. The user typed it, and `peep scan
 *   http://localhost:3000` against a local build is a supported workflow.
 * - Subresource URLs harvested from that page's HTML are not. They may only be
 *   fetched when they resolve to a public address, or when they point back at
 *   the host being scanned (same-origin, already trusted by the line above).
 */

/** Default response ceiling. `AbortSignal.timeout` bounds time, not bytes. */
export const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024; // 10 MB

/** IPv4 ranges that must never be reachable from page-controlled input. */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64/10 CGNAT
  if (a === 169 && b === 254) return true; // link-local — cloud metadata lives here
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 0) return true; // 192.0.0/24 IETF protocol assignments
  if (a === 192 && b === 168) return true; // private
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast + reserved (224/4, 240/4)
  return false;
}

/**
 * Expand any IPv6 form to its 8 numeric groups.
 *
 * Textual matching is not enough: `new URL()` rewrites
 * `[::ffff:127.0.0.1]` to `::ffff:7f00:1`, so a guard that only looked for a
 * dotted-quad tail let a mapped loopback address straight through.
 */
function ipv6Groups(addr: string): number[] | null {
  let s = addr.toLowerCase().split('%')[0]; // strip zone index
  // Fold a trailing dotted-quad (::ffff:1.2.3.4) into two hex groups
  const dotted = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const p = dotted[2].split('.').map(Number);
    if (p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    s = `${dotted[1]}${((p[0] << 8) | p[1]).toString(16)}:${((p[2] << 8) | p[3]).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
  let groups: string[];
  if (halves.length === 1) {
    groups = head;
  } else {
    const fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = [...head, ...Array<string>(fill).fill('0'), ...tail];
  }
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => parseInt(g, 16));
  return nums.every((n) => Number.isInteger(n) && n >= 0 && n <= 0xffff) ? nums : null;
}

function isPrivateIPv6(ip: string): boolean {
  const g = ipv6Groups(ip);
  if (!g) return true; // unparseable — fail closed
  const leadingZero = (count: number) => g.slice(0, count).every((x) => x === 0);
  // :: (unspecified) and ::1 (loopback)
  if (leadingZero(7) && (g[7] === 0 || g[7] === 1)) return true;
  // IPv4-mapped ::ffff:a.b.c.d and deprecated IPv4-compatible ::a.b.c.d
  if ((leadingZero(5) && g[5] === 0xffff) || leadingZero(6)) {
    const v4 = [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff].join('.');
    return isPrivateIPv4(v4);
  }
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  return false;
}

/** True when an IP literal is in a range a scanned page must not reach. */
export function isPrivateAddress(ip: string): boolean {
  const kind = isIP(ip);
  if (kind === 4) return isPrivateIPv4(ip);
  if (kind === 6) return isPrivateIPv6(ip);
  return true; // not an IP literal at all — caller resolves first
}

/**
 * Decide whether a page-derived URL may be fetched.
 *
 * `targetHost` is the host peep was pointed at; a subresource on that same host
 * is allowed without a resolution check, which keeps local/LAN scanning working.
 */
export async function isFetchAllowed(
  rawUrl: string,
  targetHost: string,
): Promise<{ allowed: boolean; reason?: string }> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { allowed: false, reason: 'unparseable URL' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { allowed: false, reason: `blocked scheme ${url.protocol}` };
  }

  const host = url.hostname.replace(/^\[|\]$/g, ''); // unwrap IPv6 literal brackets

  // Same host as the scan target: already trusted by virtue of being the target.
  if (host.toLowerCase() === targetHost.toLowerCase()) return { allowed: true };

  if (isIP(host)) {
    return isPrivateAddress(host)
      ? { allowed: false, reason: `private address ${host}` }
      : { allowed: true };
  }

  // Hostname: resolve and reject if *any* answer is private. A name that
  // resolves to both a public and a private address is a rebinding attempt.
  try {
    const answers = await lookup(host, { all: true });
    if (answers.length === 0) return { allowed: false, reason: 'no DNS answer' };
    for (const { address } of answers) {
      if (isPrivateAddress(address)) {
        return { allowed: false, reason: `${host} resolves to private ${address}` };
      }
    }
    return { allowed: true };
  } catch {
    return { allowed: false, reason: `cannot resolve ${host}` };
  }
}

/**
 * Read a response body with a hard byte ceiling.
 *
 * `AbortSignal.timeout` caps how long a response may take, not how much it may
 * send — a target streaming quickly can exhaust memory well inside the timeout.
 * Truncation is deterministic (same cap, same prefix), so content hashes stay
 * comparable across domains, which is what correlation relies on.
 */
export async function readCapped(
  resp: Response,
  maxBytes: number = DEFAULT_MAX_RESPONSE_BYTES,
): Promise<string> {
  if (!resp.body) return '';
  const reader = resp.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      if (total + chunk.length > maxBytes) {
        chunks.push(chunk.subarray(0, maxBytes - total));
        await reader.cancel();
        break;
      }
      chunks.push(chunk);
      total += chunk.length;
    }
  } catch {
    // Partial body is still usable for fingerprinting; return what arrived.
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Byte-capped binary read, for the favicon hash. */
export async function readCappedBuffer(
  resp: Response,
  maxBytes: number = DEFAULT_MAX_RESPONSE_BYTES,
): Promise<Buffer> {
  if (!resp.body) return Buffer.alloc(0);
  const reader = resp.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = Buffer.from(value);
      if (total + chunk.length > maxBytes) {
        chunks.push(chunk.subarray(0, maxBytes - total));
        await reader.cancel();
        break;
      }
      chunks.push(chunk);
      total += chunk.length;
    }
  } catch {
    // Partial body is still hashable; return what arrived.
  }
  return Buffer.concat(chunks);
}
