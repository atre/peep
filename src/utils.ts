import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { DnsResult, ScanningConfig, ScanResult } from './types.js';
import { DKIM_SELECTORS } from './scanners/dns.js';

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

// ── Local-target scan hygiene (explicit http:// targets) ──

/**
 * Status-line reason used for TLS/WHOIS when the scanner is skipped outright
 * because the user passed an explicit `http://` target (e.g. `localhost:9999`
 * LAN/staging) — that target was never expected to have TLS or a registrable
 * WHOIS domain in the first place, so a raw ENOTFOUND/"Invalid domain" error
 * would just be noise. Shared by the scanner gate (src/scanners/index.ts) and
 * the text renderer (src/commands/scan.ts) so the two stay in lockstep.
 */
export const EXPLICIT_HTTP_TARGET_SKIP_REASON = 'skipped (explicit http:// target)';

/**
 * True when a scan's target URL is an explicit `http://` one — set together
 * with `ScanningConfig.scheme` in src/index.ts (only when every domain arg on
 * the command line started with `http://`). Derived from the per-result `url`
 * field rather than threading `ScanningConfig` through every caller (findings,
 * text renderers, check gates) that only has a `ScanResult` in hand.
 */
export function isExplicitHttpTarget(result: Pick<ScanResult, 'url'>): boolean {
  return result.url.startsWith('http://');
}

// ── Email authentication (SPF / DMARC) ──

export interface EmailAuthCheck {
  name: 'SPF' | 'DMARC' | 'DKIM';
  rating: 'good' | 'warning' | 'missing' | 'bad';
  /** One-line human summary, e.g. `-all · include: _spf.google.com`. */
  value: string;
  detail: string;
}

/**
 * Judge a domain's SPF + DMARC posture from the dns scanner output. Returns
 * null when the dns scanner didn't run (or is a pre-0.2 JSON without the
 * fields) — "unknown" must not read as "missing".
 *
 * `explicitHttpTarget` (true for a `localhost:PORT`-shaped explicit http://
 * target) returns `[]` instead — evaluated-and-clean, not "didn't run" — so a
 * bare local target doesn't fire crit SPF/DMARC findings for DNS it was never
 * expected to have. Deliberately not folded into the `!dns` null case above:
 * the DNS scanner may still have run and returned real (empty) data; this is
 * about suppressing the derived judgement, not the scan itself.
 */
export function emailAuthChecks(dns: DnsResult | null | undefined, explicitHttpTarget = false): EmailAuthCheck[] | null {
  if (!dns || dns.spf === undefined || dns.dmarc === undefined) return null;
  if (explicitHttpTarget) return [];
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

  const dkim = dns.dkim ?? [];
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
      const dkimHint = dkim.length ? ' — DKIM present, safe to move to p=quarantine' : '';
      out.push({ name: 'DMARC', rating: 'warning', value, detail: `p=none — monitoring only, spoofed mail is still delivered${dkimHint}` });
    } else {
      out.push({ name: 'DMARC', rating: 'bad', value, detail: `DMARC record present but policy is ${dmarc.policy ? `"${dmarc.policy}"` : 'missing'} — malformed` });
    }
  }

  // DKIM is informational — probed only at common selectors, so absence here
  // doesn't prove the domain has none (their selector may not be in the list).
  if (dkim.length) {
    out.push({ name: 'DKIM', rating: 'good', value: dkim.map((d) => d.selector).join(', '), detail: `DKIM key found at selector(s): ${dkim.map((d) => d.selector).join(', ')}` });
  } else {
    out.push({ name: 'DKIM', rating: 'warning', value: 'none', detail: `no DKIM at common selectors (probed: ${DKIM_SELECTORS.join(', ')})` });
  }

  return out;
}

/**
 * Copy-pasteable DMARC remediation for `check`'s ✗ line — the exact record to
 * publish at `_dmarc.<domain>` to clear a non-good DMARC rating. Null when
 * DMARC is already good (p=reject/quarantine at pct=100 — nothing to fix) or
 * the dns scanner didn't run.
 *
 * The rua mailbox prefers a real address already surfaced by the scan (an
 * existing DMARC rua even on the weak record being replaced, then
 * security.txt/CAA contacts) over a guessed `postmaster@<domain>` — still
 * copy-pasteable per-domain, but not fabricated when better data exists.
 */
export function dmarcFixSuggestion(domain: string, r: ScanResult): string | null {
  const dmarc = r.dns?.dmarc;
  if (r.dns === undefined || r.dns === null) return null; // dns scanner didn't run

  const identifiers = collectExposedIdentifiers(r);
  const bySource = (source: string) => identifiers.find((i) => i.source === source)?.value;
  const rua = bySource('DNS DMARC rua') ?? bySource('security.txt Contact') ?? bySource('DNS CAA iodef') ?? bySource('HTML mailto') ?? `postmaster@${domain}`;

  if (!dmarc) {
    return `→ fix: set _dmarc TXT "v=DMARC1; p=quarantine; rua=mailto:${rua}"`;
  }
  if (dmarc.policy === 'reject' || dmarc.policy === 'quarantine') {
    if (dmarc.pct !== null && dmarc.pct < 100) {
      return `→ fix: set _dmarc TXT "v=DMARC1; p=${dmarc.policy}; pct=100; rua=mailto:${rua}"`;
    }
    return null; // good — nothing to fix
  }
  // p=none, or malformed/missing p= tag — either way, quarantine is the safe next step
  return `→ fix: set _dmarc TXT "v=DMARC1; p=quarantine; rua=mailto:${rua}"`;
}

export interface ExposedIdentifier {
  kind: 'email';
  value: string;
  source: string;
}

/**
 * Every email address a scan surfaced, with where it came from — DMARC
 * rua/ruf, CAA iodef, security.txt Contact, and mailto:/body-text on the page
 * itself. Feeds the scan output's "Exposed identifiers" line and, fleet-wide,
 * shared-contact-email correlation.
 */
export function collectExposedIdentifiers(r: ScanResult): ExposedIdentifier[] {
  const out: ExposedIdentifier[] = [];
  const seen = new Set<string>();
  const add = (value: string, source: string) => {
    const v = value.toLowerCase();
    const key = `${v}|${source}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind: 'email', value: v, source });
  };

  const dmarc = r.dns?.dmarc;
  for (const addr of dmarc?.rua ?? []) add(addr, 'DNS DMARC rua');
  for (const addr of dmarc?.ruf ?? []) add(addr, 'DNS DMARC ruf');

  for (const caa of r.dns?.caa ?? []) {
    const m = caa.match(/^iodef\s+(?:mailto:)?(\S+@\S+)$/i);
    if (m?.[1]) add(m[1], 'DNS CAA iodef');
  }

  for (const contact of r.robots?.securityTxtSummary?.contacts ?? []) {
    const email = contact.replace(/^mailto:/i, '');
    if (/^\S+@\S+$/.test(email)) add(email, 'security.txt Contact');
  }

  for (const email of r.html?.emails ?? []) add(email, 'HTML mailto');

  return out;
}

/**
 * Reduce one `evaluateCheck()` failure string (see commands/check.ts) down to
 * a stable rollup key: a check `name` plus, for per-route SEO/route checks,
 * the `route` it fired on. Used by `fleet` to group "same check fails on
 * N/10 domains" instead of repeating the identical line per domain.
 *
 * Deliberately pattern-matches the fixed set of failure strings evaluateCheck
 * produces rather than changing its return shape (`failures: string[]`) —
 * that shape is asserted on directly by ~30 check.test.ts cases. A failure
 * shape evaluateCheck doesn't recognize still rolls up fine: it falls back to
 * using the full text as the key, just without route-stripping.
 */
export function classifyCheckFailure(failure: string): { route: string | null; name: string } {
  let m = failure.match(/^SEO check "([^"]+)" not passing on (\S+) —/);
  if (m) return { route: m[2], name: m[1] };

  m = failure.match(/^SEO score \d+\/100 on (\S+) is below --min-seo/);
  if (m) return { route: m[1], name: 'SEO score below --min-seo' };

  m = failure.match(/^Route (\S+) (?:returned HTTP \d+|unreachable)$/);
  if (m) return { route: m[1], name: 'Route unreachable' };

  m = failure.match(/^Route (\S+) is NOINDEX/);
  if (m) return { route: m[1], name: 'Route NOINDEX' };

  if (/^HTTP \d+ —/.test(failure)) return { route: null, name: 'Site unreachable (HTTP error)' };
  if (failure.startsWith('Adult content detected')) return { route: null, name: 'Adult content on clean cluster' };
  if (failure.startsWith('Site is NOINDEX')) return { route: null, name: 'Site NOINDEX' };
  if (failure.startsWith('Security score')) return { route: null, name: 'Security score below threshold' };
  if (failure.startsWith('security.txt not found')) return { route: null, name: 'security.txt missing' };

  m = failure.match(/^(SPF|DMARC|DKIM) (missing|weak) —/);
  if (m) return { route: null, name: `${m[1]} ${m[2]}` };

  m = failure.match(/^Critical scanner error \[(\w+)\]:/);
  if (m) return { route: null, name: `Critical scanner error [${m[1]}]` };

  return { route: null, name: failure };
}
