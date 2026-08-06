import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ScanningConfig } from './types.js';

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
