import * as http from 'node:http';
import * as https from 'node:https';
import { URL as NodeURL } from 'node:url';
import type { HttpResult } from '../types.js';
import { readCapped } from '../fetch-guard.js';
import type { ScanningConfig } from '../types.js';
import { origin } from '../utils.js';
import { withResolverWarning } from '../resolver.js';

export interface HttpScanOutput {
  result: HttpResult;
  body: string | null;
}

/** Request headers for a scan fetch. Accept-Language is included only when the
 *  caller explicitly set one (`--lang`) — sending none is the default and
 *  matches Googlebot, so a locale-default site isn't skewed toward EN.
 *  `Host` is included only when `--host` set a hostOverride. */
export function buildRequestHeaders(config: ScanningConfig): Record<string, string> {
  const headers: Record<string, string> = {
    'User-Agent': config.userAgent,
    Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  };
  if (config.acceptLanguage) headers['Accept-Language'] = config.acceptLanguage;
  if (config.hostOverride) headers['Host'] = config.hostOverride;
  return headers;
}

/**
 * Fetch equivalent for one request hop. When `config.hostOverride` (--host) is
 * set, routes through Node's raw http/https client instead of the global
 * fetch() — `Host` is a WHATWG-forbidden request-header name, and fetch()
 * (undici) silently drops it rather than sending it, so a spoofed Host header
 * can only be delivered this way. TLS SNI is spoofed the same way via
 * `servername`. The `url` connected to is always the literal one passed in —
 * only what's presented as Host/SNI changes.
 */
function doFetch(url: string, config: ScanningConfig, signal: AbortSignal): Promise<Response> {
  if (!config.hostOverride) {
    return fetch(url, { headers: buildRequestHeaders(config), redirect: 'manual', signal });
  }
  return rawFetchWithHostOverride(url, config);
}

function rawFetchWithHostOverride(url: string, config: ScanningConfig): Promise<Response> {
  const target = new NodeURL(url);
  const isHttps = target.protocol === 'https:';
  const client = isHttps ? https : http;
  const headers = buildRequestHeaders(config);

  return new Promise((resolve, reject) => {
    const req = client.request(
      {
        hostname: target.hostname,
        port: target.port || (isHttps ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        method: 'GET',
        headers,
        timeout: config.timeout,
        ...(isHttps ? { servername: config.hostOverride, rejectUnauthorized: false } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          const respHeaders = new Headers();
          for (const [key, value] of Object.entries(res.headers)) {
            if (value === undefined) continue;
            for (const v of Array.isArray(value) ? value : [value]) respHeaders.append(key, v);
          }
          resolve(new Response(Buffer.concat(chunks), {
            status: res.statusCode || 502,
            statusText: res.statusMessage ?? '',
            headers: respHeaders,
          }));
        });
      },
    );
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.end();
  });
}

export async function scanHttp(domain: string, config: ScanningConfig): Promise<HttpScanOutput> {
  const url = origin(domain, config.scheme);
  const start = Date.now();

  // Follow redirects manually to capture the full chain (cap at 10)
  const redirectChain: string[] = [];
  let currentUrl = url;
  let response: Response | null = null;
  let lastError: unknown = null;
  // Tracks the URL that actually produced `response` — needed because a raw
  // (hostOverride) Response built by rawFetchWithHostOverride has no `.url`
  // of its own (only fetch()'s real Response does), and the http-fallback hop
  // below reassigns `response` without ever updating `currentUrl`.
  let finalRequestUrl = currentUrl;

  for (let hop = 0; hop < 10; hop++) {
    try {
      const res = await doFetch(currentUrl, config, AbortSignal.timeout(config.timeout));

      // 3xx redirect — follow manually
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        if (location) {
          redirectChain.push(location);
          // Resolve relative URLs
          try {
            currentUrl = new URL(location, currentUrl).toString();
          } catch {
            currentUrl = location;
          }
          continue;
        }
      }

      response = res;
      finalRequestUrl = currentUrl;
      break;
    } catch (e) {
      lastError = e;
      // Try HTTP fallback on first attempt if HTTPS failed
      // (moot when the scan already started on http — currentUrl guard)
      if (hop === 0 && currentUrl.startsWith('https://')) {
        try {
          const httpUrl = `http://${domain}`;
          const res = await doFetch(httpUrl, config, AbortSignal.timeout(config.timeout));

          if (res.status >= 300 && res.status < 400) {
            const location = res.headers.get('location');
            if (location) {
              redirectChain.push(location);
              try {
                currentUrl = new URL(location, httpUrl).toString();
              } catch {
                currentUrl = location;
              }
              continue;
            }
          }

          response = res;
          finalRequestUrl = httpUrl;
          break;
        } catch {
          // both failed
        }
      }
      break;
    }
  }

  if (!response) {
    // dns.lookup() (used internally by fetch) may have attached a
    // peepResolverWarning when the OS resolver disagreed with the public one —
    // see src/resolver.ts. Surface it so `errors` explains *why*, not just ENOTFOUND.
    const err = lastError instanceof Error ? lastError : new Error('HTTP request failed');
    throw withResolverWarning(err);
  }

  const timing = Date.now() - start;

  // Read body for downstream scanners
  let body: string | null = null;
  try {
    if (response.ok || response.status < 400) {
      body = await readCapped(response);
    }
  } catch {
    // Body read failed, downstream scanners will cope
  }

  // Collect headers as plain object
  const headers: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value;
  });

  // Extract set-cookie headers
  const setCookies: string[] = [];
  const rawCookies = response.headers.getSetCookie?.() ?? [];
  setCookies.push(...rawCookies);

  return {
    result: {
      statusCode: response.status,
      headers,
      serverHeader: headers['server'] ?? null,
      poweredBy: headers['x-powered-by'] ?? null,
      contentType: headers['content-type'] ?? null,
      timing,
      redirectChain,
      setCookies,
      xRobotsTag: headers['x-robots-tag'] ?? null,
      finalUrl: response.url || finalRequestUrl || null,
      acceptLanguage: config.acceptLanguage ?? null,
    },
    body,
  };
}
