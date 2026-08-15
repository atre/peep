import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { DnsResult, ScanningConfig } from './types.js';

/** Write `content` to `outFile` (resolved against cwd) and return the absolute path.
 *  Shared by every command that supports --out so the flag isn't a per-command no-op. */
export function writeOutputFile(outFile: string, content: string): string {
  const full = resolve(process.cwd(), outFile);
  writeFileSync(full, content, 'utf-8');
  return full;
}

export function md5(input: string): string {
  return createHash('md5').update(input).digest('hex');
}

export function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

export function shortHash(input: string): string {
  return md5(input).slice(0, 12);
}

export function normalizeDomain(domain: string): string {
  return domain.replace(/^https?:\/\//i, '').replace(/[/?#].*$/, '').replace(/\/+$/, '').toLowerCase();
}

/**
 * Returns the path/query/fragment that normalizeDomain() discards, or '' when
 * the input is a bare host. A lone trailing slash counts as nothing meaningful,
 * so 'example.com/' → '' but 'example.com/de' → '/de'. Used to warn the user
 * that peep scans the apex and can't audit a specific path.
 */
export function strippedPath(input: string): string {
  const match = input.replace(/^https?:\/\//i, '').match(/[/?#].*$/);
  if (!match) return '';
  const rest = match[0];
  return /^\/+$/.test(rest) ? '' : rest;
}

export function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Origin for scanner fetches — honors an explicit http:// scan target. */
export function origin(domain: string, scheme?: 'https' | 'http'): string {
  return `${scheme ?? 'https'}://${domain}`;
}

export function domainToUrl(domain: string): string {
  if (domain.startsWith('http://') || domain.startsWith('https://')) return domain;
  return `https://${domain}`;
}

export function extractAll(html: string, pattern: RegExp): string[] {
  const results: string[] = [];
  let match: RegExpExecArray | null;
  const re = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
  while ((match = re.exec(html)) !== null) {
    if (match[1]) results.push(match[1]);
    if (match[0].length === 0) re.lastIndex++; // prevent infinite loop on zero-length match
  }
  return results;
}

export function uniqueBy<T>(arr: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return arr.filter((item) => {
    const k = key(item);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

const COLORS = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  reset: '\x1b[0m',
} as const;

export function c(color: keyof typeof COLORS, text: string): string {
  if (!process.stdout.isTTY) return text;
  return `${COLORS[color]}${text}${COLORS.reset}`;
}

export function severityColor(severity: 'critical' | 'high' | 'medium' | 'low'): keyof typeof COLORS {
  const map = { critical: 'red', high: 'yellow', medium: 'cyan', low: 'gray' } as const;
  return map[severity];
}

/** Color for a 0–100 score: green ≥ 80, yellow ≥ `warn` (default 50), red below. */
export function scoreColor(score: number, warn = 50): keyof typeof COLORS {
  if (score >= 80) return 'green';
  if (score >= warn) return 'yellow';
  return 'red';
}

/**
 * Resolve the effective scanning config from CLI flags. `--skip-content-hash` wins
 * over `--hash-content` and the config default; the resolved `hashContent` is always
 * set explicitly so the flag isn't silently dropped when the default is true.
 */
export function resolveScanningConfig(
  flags: Record<string, string | boolean>,
  scanning: ScanningConfig,
): ScanningConfig {
  const skipContentHash = flags['skip-content-hash'] === true;
  const hashContent = skipContentHash
    ? false
    : (flags['hash-content'] === true || scanning.hashContent);
  return { ...scanning, hashContent };
}

/**
 * Parse the `--pages` flag, which accepts either a count (`--pages 5` → top N
 * sitemap pages, merged form endpoints only) or an explicit comma-separated route
 * list (`--pages /de,/fr/contact` → per-page SEO/hreflang audit of those paths).
 * A bare number is a count; anything else is treated as routes.
 */
export function parsePagesFlag(flags: Record<string, string | boolean>): { pages: number; pageRoutes: string[] } {
  const raw = typeof flags.pages === 'string' ? flags.pages.trim() : '';
  if (/^\d+$/.test(raw)) return { pages: parseInt(raw, 10), pageRoutes: [] };
  const pageRoutes = raw ? raw.split(',').map((s) => s.trim()).filter(Boolean) : [];
  return { pages: 0, pageRoutes };
}

/**
 * Map a domain's nameservers to a DNS provider that offers one-click/one-toggle
 * DNSSEC. Used to turn an "unsigned" DNSSEC fact into an actionable finding: if the
 * operator is already on Cloudflare, leaving DNSSEC off is a choice, not a constraint.
 */
const ONE_CLICK_DNSSEC_NS: Array<{ pattern: RegExp; name: string }> = [
  { pattern: /(^|\.)cloudflare\.com$/i, name: 'Cloudflare' },
  { pattern: /(^|\.)dnsimple\.com$/i, name: 'DNSimple' },
];

export function oneClickDnssecProvider(nameservers: string[]): string | null {
  for (const ns of nameservers) {
    const host = ns.trim().toLowerCase().replace(/\.$/, '');
    for (const { pattern, name } of ONE_CLICK_DNSSEC_NS) {
      if (pattern.test(host)) return name;
    }
  }
  return null;
}

export function getCluster(domain: string, clusters: Record<string, string[]>): string | null {
  for (const [name, domains] of Object.entries(clusters)) {
    if (domains.includes(domain)) return name;
  }
  return null;
}

/**
 * A cluster is an adult ("red") cluster when its name starts with "adult".
 * Case-insensitive on purpose: a `.peeprc` cluster named "Adult" used to read
 * as clean, which both failed the deploy gate for correctly-configured adult
 * sites and raised spurious cross-cluster criticals for them.
 */
export function isAdultCluster(cluster: string | null | undefined): boolean {
  return cluster != null && cluster.trim().toLowerCase().startsWith('adult');
}

/**
 * Human meaning of an error status, with the Cloudflare 52x family spelled out —
 * "526" alone sends people to a search engine; "origin certificate invalid"
 * tells them what to fix.
 */
export function describeHttpStatus(status: number): string {
  const known: Record<number, string> = {
    400: 'bad request',
    401: 'authentication required',
    403: 'forbidden — bot protection or access control blocked the request',
    404: 'not found — root path returns 404',
    410: 'gone',
    429: 'rate limited',
    500: 'internal server error',
    502: 'bad gateway — upstream returned an invalid response',
    503: 'service unavailable — maintenance or overloaded',
    504: 'gateway timeout',
    520: 'Cloudflare: origin returned an unknown/empty response',
    521: 'Cloudflare: origin web server is down (connection refused)',
    522: 'Cloudflare: connection to origin timed out',
    523: 'Cloudflare: origin unreachable (DNS/routing)',
    524: 'Cloudflare: origin timed out sending a response',
    525: 'Cloudflare: TLS handshake with origin failed',
    526: 'Cloudflare: origin TLS certificate invalid (Full (strict) mode)',
    530: 'Cloudflare: origin DNS error / tunnel or access blocked',
  };
  return known[status] ?? (status >= 500 ? 'server error' : 'client error');
}

/** True when the response is an error page rather than the site itself. */
export function isErrorStatus(status: number | null | undefined): status is number {
  return typeof status === 'number' && status >= 400;
}

// ── Email authentication (SPF / DMARC) ──

export interface EmailAuthCheck {
  name: 'SPF' | 'DMARC';
  rating: 'good' | 'warning' | 'missing' | 'bad';
  /** One-line human summary, e.g. `-all · include: _spf.google.com`. */
  value: string;
  detail: string;
}

/**
 * Judge a domain's SPF + DMARC posture from the dns scanner output. Returns
 * null when the dns scanner didn't run (or is a pre-0.2 JSON without the
 * fields) — "unknown" must not read as "missing".
 */
export function emailAuthChecks(dns: DnsResult | null | undefined): EmailAuthCheck[] | null {
  if (!dns || dns.spf === undefined || dns.dmarc === undefined) return null;
  const out: EmailAuthCheck[] = [];

  const spf = dns.spf;
  if (!spf) {
    out.push({ name: 'SPF', rating: 'missing', value: 'none', detail: 'No SPF record — any server can send mail as this domain (publish `v=spf1 -all` if the domain never sends)' });
  } else {
    const parts: string[] = [];
    if (spf.includes.length) parts.push(`include: ${spf.includes.join(', ')}`);
    if (spf.ip4.length || spf.ip6.length) parts.push(`ip: ${[...spf.ip4, ...spf.ip6].join(', ')}`);
    if (spf.redirect) parts.push(`redirect=${spf.redirect}`);
    const value = [spf.all ?? '(no all)', ...parts].join(' · ');
    if (spf.all === '+all') out.push({ name: 'SPF', rating: 'bad', value, detail: 'SPF ends in +all — every sender passes, record is meaningless' });
    else if (spf.all === '?all' || spf.all === null) out.push({ name: 'SPF', rating: 'warning', value, detail: `SPF has ${spf.all ?? 'no'} terminal — unlisted senders are neutral, not rejected` });
    else if (spf.includes.length + (spf.redirect ? 1 : 0) > 10) out.push({ name: 'SPF', rating: 'warning', value, detail: 'More than 10 include/redirect terms — exceeds the SPF DNS-lookup limit (permerror)' });
    else out.push({ name: 'SPF', rating: 'good', value, detail: spf.all === '-all' ? 'hard fail for unlisted senders' : 'soft fail for unlisted senders' });
  }

  const dmarc = dns.dmarc;
  if (!dmarc) {
    out.push({ name: 'DMARC', rating: 'missing', value: 'none', detail: 'No _dmarc record — SPF/DKIM failures are not enforced, spoofed mail is still delivered' });
  } else {
    const parts = [`p=${dmarc.policy ?? '?'}`];
    if (dmarc.subdomainPolicy) parts.push(`sp=${dmarc.subdomainPolicy}`);
    if (dmarc.pct !== null && dmarc.pct !== 100) parts.push(`pct=${dmarc.pct}`);
    if (dmarc.rua.length) parts.push(`rua=${dmarc.rua.join(',')}`);
    if (dmarc.ruf.length) parts.push(`ruf=${dmarc.ruf.join(',')}`);
    const value = parts.join(' ');
    if (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') {
      if (dmarc.pct !== null && dmarc.pct < 100) out.push({ name: 'DMARC', rating: 'warning', value, detail: `p=${dmarc.policy} applies to only ${dmarc.pct}% of mail` });
      else out.push({ name: 'DMARC', rating: 'good', value, detail: `p=${dmarc.policy} — spoofed mail is ${dmarc.policy === 'reject' ? 'rejected' : 'quarantined'}` });
    } else if (dmarc.policy === 'none') {
      out.push({ name: 'DMARC', rating: 'warning', value, detail: 'p=none — monitoring only, spoofed mail is still delivered' });
    } else {
      out.push({ name: 'DMARC', rating: 'bad', value, detail: `DMARC record present but policy is ${dmarc.policy ? `"${dmarc.policy}"` : 'missing'} — malformed` });
    }
  }
  return out;
}
