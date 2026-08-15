import type { SecurityResult, SecurityHeader } from '../types.js';

interface HeaderCheck {
  name: string;
  header: string;
  evaluate: (value: string | null) => { rating: SecurityHeader['rating']; detail: string };
}

const HEADER_CHECKS: HeaderCheck[] = [
  {
    name: 'Strict-Transport-Security',
    header: 'strict-transport-security',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'HSTS not set — site can be accessed over plain HTTP' };
      const maxAge = v.match(/max-age=(\d+)/)?.[1];
      const num = maxAge ? parseInt(maxAge, 10) : 0;
      if (num >= 31536000 && /includeSubDomains/i.test(v)) {
        const preload = /preload/i.test(v) ? ' + preload' : '';
        return { rating: 'good', detail: `max-age=${num}, includeSubDomains${preload}` };
      }
      if (num >= 31536000) return { rating: 'warning', detail: `max-age OK but missing includeSubDomains` };
      return { rating: 'warning', detail: `max-age=${num} is below recommended 31536000 (1 year)` };
    },
  },
  {
    name: 'Content-Security-Policy',
    header: 'content-security-policy',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'No CSP — vulnerable to XSS and injection attacks' };
      // Parse CSP directives individually — only flag unsafe-inline/unsafe-eval in script-src
      // style-src 'unsafe-inline' is standard practice (Tailwind, utility CSS) and acceptable
      const directives = parseCspDirectives(v);
      const scriptSrc = directives['script-src'] ?? directives['default-src'] ?? [];
      const hasUnsafeInline = scriptSrc.includes("'unsafe-inline'");
      const hasUnsafeEval = scriptSrc.includes("'unsafe-eval'");
      const styleSrc = directives['style-src'];
      const styleNote = styleSrc?.includes("'unsafe-inline'") ? ' (style-src unsafe-inline — acceptable)' : '';
      if (hasUnsafeInline && hasUnsafeEval) return { rating: 'warning', detail: `CSP present but script-src allows unsafe-inline and unsafe-eval${styleNote}` };
      if (hasUnsafeInline) return { rating: 'warning', detail: `CSP present but script-src allows unsafe-inline${styleNote}` };
      if (hasUnsafeEval) return { rating: 'warning', detail: `CSP present but script-src allows unsafe-eval${styleNote}` };
      return { rating: 'good', detail: `CSP configured${styleNote}` };
    },
  },
  {
    name: 'X-Frame-Options',
    header: 'x-frame-options',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'No X-Frame-Options — site can be embedded in iframes (clickjacking risk)' };
      if (/^DENY$/i.test(v)) return { rating: 'good', detail: 'DENY — no framing allowed' };
      if (/^SAMEORIGIN$/i.test(v)) return { rating: 'good', detail: 'SAMEORIGIN — same-origin framing only' };
      return { rating: 'warning', detail: `Unexpected value: ${v}` };
    },
  },
  {
    name: 'X-Content-Type-Options',
    header: 'x-content-type-options',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'No X-Content-Type-Options — MIME sniffing possible' };
      if (/nosniff/i.test(v)) return { rating: 'good', detail: 'nosniff' };
      return { rating: 'warning', detail: `Unexpected value: ${v}` };
    },
  },
  {
    name: 'Referrer-Policy',
    header: 'referrer-policy',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'No Referrer-Policy — full URL may leak in referrer headers' };
      const strict = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
      if (strict.some((s) => v.toLowerCase().includes(s))) return { rating: 'good', detail: v };
      if (v.toLowerCase() === 'unsafe-url') return { rating: 'bad', detail: 'unsafe-url leaks full URL to all origins' };
      return { rating: 'warning', detail: v };
    },
  },
  {
    name: 'Permissions-Policy',
    header: 'permissions-policy',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'No Permissions-Policy — browser features unrestricted' };
      return { rating: 'good', detail: v.length > 80 ? v.slice(0, 77) + '...' : v };
    },
  },
  {
    name: 'Cross-Origin-Opener-Policy',
    header: 'cross-origin-opener-policy',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'No COOP — cross-origin window access unrestricted' };
      if (/same-origin/i.test(v)) return { rating: 'good', detail: v };
      if (/same-origin-allow-popups/i.test(v)) return { rating: 'good', detail: v };
      return { rating: 'warning', detail: v };
    },
  },
  {
    name: 'Cross-Origin-Embedder-Policy',
    header: 'cross-origin-embedder-policy',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'No COEP — cross-origin resources loaded without opt-in' };
      if (/require-corp/i.test(v)) return { rating: 'good', detail: v };
      if (/credentialless/i.test(v)) return { rating: 'good', detail: v };
      return { rating: 'warning', detail: v };
    },
  },
  {
    name: 'Cross-Origin-Resource-Policy',
    header: 'cross-origin-resource-policy',
    evaluate: (v) => {
      if (!v) return { rating: 'missing', detail: 'No CORP — resources can be embedded by any origin' };
      if (/same-origin/i.test(v)) return { rating: 'good', detail: v };
      if (/same-site/i.test(v)) return { rating: 'good', detail: v };
      if (/cross-origin/i.test(v)) return { rating: 'good', detail: `${v} — public resource sharing` };
      return { rating: 'warning', detail: v };
    },
  },
  {
    name: 'Server header',
    header: 'server',
    evaluate: (v) => {
      if (!v) return { rating: 'good', detail: 'Not disclosed' };
      // Check for version disclosure
      if (/\d+\.\d+/.test(v)) return { rating: 'warning', detail: `${v} — version disclosed` };
      return { rating: 'good', detail: v };
    },
  },
  {
    name: 'X-Powered-By',
    header: 'x-powered-by',
    evaluate: (v) => {
      if (!v) return { rating: 'good', detail: 'Not disclosed' };
      return { rating: 'warning', detail: `${v} — technology stack disclosed` };
    },
  },
];

export function scanSecurity(
  headers: Record<string, string>,
  opts?: { hasSecurityTxt?: boolean; commentCount?: number; scriptSources?: string[]; domain?: string },
): SecurityResult {
  const results: SecurityHeader[] = [];
  let points = 0;
  let maxPoints = 0;

  for (const check of HEADER_CHECKS) {
    const value = headers[check.header] ?? null;
    const { rating, detail } = check.evaluate(value);
    results.push({
      name: check.name,
      present: value !== null,
      value,
      rating,
      detail,
    });

    // Score: good=full, warning=half, missing/bad=0
    const weight = check.name === 'X-Powered-By' || check.name === 'Server header' ? 5 : 15;
    maxPoints += weight;
    if (rating === 'good') points += weight;
    else if (rating === 'warning') points += Math.floor(weight / 2);
  }

  // security.txt presence is a best-practice indicator (+5 bonus points)
  // Only scored when robots scanner actually ran (hasSecurityTxt is boolean, not undefined)
  if (opts?.hasSecurityTxt != null) {
    const secTxtWeight = 5;
    maxPoints += secTxtWeight;
    if (opts.hasSecurityTxt) {
      points += secTxtWeight;
      results.push({
        name: 'security.txt',
        present: true,
        value: 'present',
        rating: 'good',
        detail: 'security.txt published — responsible disclosure contact available',
      });
    } else {
      results.push({
        name: 'security.txt',
        present: false,
        value: null,
        rating: 'missing',
        detail: 'No security.txt — consider adding /.well-known/security.txt',
      });
    }
  }

  // CORS: access-control-allow-origin: * (informational, no score impact)
  const corsHeader = headers['access-control-allow-origin'];
  if (corsHeader === '*') {
    results.push({
      name: 'Access-Control-Allow-Origin',
      present: true,
      value: '*',
      rating: 'warning',
      detail: 'CORS allows all origins (*) — acceptable for public static assets, risky for APIs with auth',
    });
  }

  // HTML comments present — OPSEC warning (informational, no score impact)
  if (opts?.commentCount && opts.commentCount > 0) {
    results.push({
      name: 'HTML comments',
      present: true,
      value: `${opts.commentCount} comment(s)`,
      rating: 'warning',
      detail: `${opts.commentCount} HTML comment(s) present — may leak internal structure or names`,
    });
  }

  // CSP script allowlist cross-reference (informational, no score impact)
  if (opts?.scriptSources?.length && opts.domain) {
    const cspRaw = headers['content-security-policy'];
    if (cspRaw) {
      const directives = parseCspDirectives(cspRaw);
      const scriptSrc = directives['script-src'] ?? directives['default-src'] ?? [];
      const cspOrigins = parseCspOrigins(scriptSrc);
      const unlisted: string[] = [];
      for (const src of opts.scriptSources) {
        if (!isOriginAllowedByCsp(src, opts.domain, cspOrigins)) {
          try {
            unlisted.push(new URL(src, `https://${opts.domain}`).hostname);
          } catch {
            unlisted.push(src);
          }
        }
      }
      const unique = [...new Set(unlisted)];
      if (unique.length > 0) {
        results.push({
          name: 'CSP script allowlist',
          present: true,
          value: unique.join(', '),
          rating: 'warning',
          detail: `Script(s) loaded from origin(s) not in CSP: ${unique.join(', ')}`,
        });
      }
    }
  }

  const score = maxPoints === 0 ? 100 : Math.round((points / maxPoints) * 100);

  return {
    score,
    headers: results,
    formProviders: extractCspFormProviders(headers),
    reportEndpoints: extractReportEndpoints(headers),
  };
}

// Cloudflare's NEL collector is injected on every proxied zone — its per-response
// token is not an operator identity, so it never counts as a shared collector.
const COMMODITY_REPORT_HOSTS = ['a.nel.cloudflare.com'];

/**
 * Collect the URLs violation reports are sent to: CSP `report-uri`, the
 * `Report-To` header (JSON groups with `endpoints[].url`, also used by NEL) and
 * the newer `Reporting-Endpoints` header (`name="url", …`). Normalized to
 * `host/path` (lowercased host, query dropped) so the same collector matches
 * across sites even when a per-site query token differs.
 */
export function extractReportEndpoints(headers: Record<string, string>): string[] {
  const urls: string[] = [];

  for (const key of ['content-security-policy', 'content-security-policy-report-only']) {
    const csp = headers[key];
    if (!csp) continue;
    // Not parseCspDirectives(): that lowercases values, and report-uri.com
    // paths / Sentry keys are case-sensitive account identifiers.
    for (const directive of csp.split(';')) {
      const tokens = directive.trim().split(/\s+/).filter(Boolean);
      if (tokens[0]?.toLowerCase() === 'report-uri') urls.push(...tokens.slice(1));
    }
  }

  const reportTo = headers['report-to'];
  if (reportTo) {
    // Header may hold several comma-separated JSON objects; the URL fields are all we need
    const re = /"url"\s*:\s*"([^"]{1,500})"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(reportTo)) !== null) urls.push(m[1]);
  }

  const reportingEndpoints = headers['reporting-endpoints'];
  if (reportingEndpoints) {
    const re = /=\s*"([^"]{1,500})"/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(reportingEndpoints)) !== null) urls.push(m[1]);
  }

  const out = new Set<string>();
  for (const raw of urls) {
    let parsed: URL;
    try { parsed = new URL(raw); } catch { continue; }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') continue;
    const host = parsed.hostname.toLowerCase();
    if (COMMODITY_REPORT_HOSTS.some((c) => host === c || host.endsWith('.' + c))) continue;
    out.add(`${host}${parsed.pathname.replace(/\/$/, '')}`);
  }
  return [...out].sort();
}

// Third-party form/booking providers worth correlating across a fleet. A shared
// provider host in two sites' CSP suggests a common operator toolkit — and unlike
// formEndpoints (which need the actual /contact/ page) the CSP is on the homepage.
const FORM_BOOKING_PROVIDERS = [
  'calendly.com', 'formspree.io', 'typeform.com', 'tally.so', 'getform.io',
  'formsubmit.co', 'basin.io', 'fabform.io', 'cal.com', 'savvycal.com',
  'acuityscheduling.com', 'hsforms.com', 'hsforms.net', 'jotform.com',
  'wufoo.com', 'formstack.com', 'youcanbook.me', 'simplybook.me',
];

// CSP directives that can name a form/booking provider host
const PROVIDER_DIRECTIVES = new Set([
  'default-src', 'script-src', 'frame-src', 'child-src', 'connect-src', 'form-action',
]);

/**
 * Extract canonical form/booking provider hosts from a Content-Security-Policy.
 * Returns e.g. ['calendly.com', 'formspree.io'] — deduped and canonicalized so a
 * '*.calendly.com' token matches a 'calendly.com' token on another site.
 */
export function extractCspFormProviders(headers: Record<string, string>): string[] {
  const csp = headers['content-security-policy'];
  if (!csp) return [];

  const directives = parseCspDirectives(csp);
  const found = new Set<string>();
  for (const name of PROVIDER_DIRECTIVES) {
    for (const token of directives[name] ?? []) {
      if (token.startsWith("'")) continue; // keywords: 'self', 'unsafe-inline', nonces…
      const host = token
        .replace(/^https?:\/\//, '')
        .replace(/^\*\./, '')
        .replace(/[/:].*$/, '');
      for (const provider of FORM_BOOKING_PROVIDERS) {
        if (host === provider || host.endsWith('.' + provider)) {
          found.add(provider);
          break;
        }
      }
    }
  }
  return [...found].sort();
}

/** Parse a CSP header value into a map of directive name → value tokens (lowercased). */
export function parseCspDirectives(csp: string): Record<string, string[]> {
  const map: Record<string, string[]> = {};
  for (const directive of csp.split(';')) {
    const tokens = directive.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0];
    if (!(name in map)) map[name] = tokens.slice(1);
  }
  return map;
}

function parseCspOrigins(tokens: string[]): { origins: string[]; hasSelf: boolean; allowsAll: boolean } {
  const origins: string[] = [];
  let hasSelf = false;
  let allowsAll = false;

  for (const token of tokens) {
    if (token === "'self'") hasSelf = true;
    else if (token === '*' || token === 'https:' || token === 'http:') allowsAll = true;
    else if (token.startsWith("'")) continue; // 'unsafe-inline', 'nonce-...', 'sha256-...', etc.
    else if (token.startsWith('data:') || token.startsWith('blob:')) continue;
    else origins.push(token.replace(/^https?:\/\//, ''));
  }

  return { origins, hasSelf, allowsAll };
}

function isOriginAllowedByCsp(
  scriptUrl: string,
  domain: string,
  cspOrigins: { origins: string[]; hasSelf: boolean; allowsAll: boolean },
): boolean {
  if (cspOrigins.allowsAll) return true;

  let hostname: string;
  try {
    hostname = new URL(scriptUrl, `https://${domain}`).hostname.toLowerCase();
  } catch {
    return true; // Can't parse — don't flag
  }

  // 'self' matches same domain
  if (cspOrigins.hasSelf && hostname === domain) return true;

  for (const origin of cspOrigins.origins) {
    if (origin === hostname) return true;
    // Wildcard: *.example.com matches sub.example.com
    if (origin.startsWith('*.') && hostname.endsWith(origin.slice(1))) return true;
  }

  return false;
}
