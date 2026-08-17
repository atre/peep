import type { ScanResult, Finding } from './types.js';
import { emailAuthChecks } from './utils.js';

function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
}

/** missing/bad → crit (would fail `peep check`); warning → warn; good → no finding. */
function severityFor(rating: string): 'crit' | 'warn' | null {
  if (rating === 'missing' || rating === 'bad') return 'crit';
  if (rating === 'warning') return 'warn';
  return null;
}

/**
 * Convert a scan's non-good checks into pulse-shaped findings — additive to
 * the existing JSON, no existing key changes. Covers security headers, SEO
 * checks, and SPF/DMARC/DKIM; informational/exploratory signals (exposed
 * identifiers, analytics vendors) are deliberately not findings — they have
 * no pass/fail rating to convert.
 */
export function toFindings(result: ScanResult): Finding[] {
  const findings: Finding[] = [];
  const domain = result.domain;

  for (const h of result.security?.headers ?? []) {
    const severity = severityFor(h.rating);
    if (!severity) continue;
    findings.push({ id: `sec:${domain}/${slug(h.name)}`, scope: 'site', severity, title: `${h.name}: ${h.detail}`, detail: h.detail, hint: `peep scan ${domain} --only security` });
  }

  for (const ch of result.seo?.checks ?? []) {
    const severity = severityFor(ch.rating);
    if (!severity) continue;
    findings.push({ id: `seo:${domain}/${slug(ch.name)}`, scope: 'site', severity, title: `${ch.name}: ${ch.detail}`, detail: ch.detail, hint: `peep scan ${domain} --only seo` });
  }

  for (const ch of emailAuthChecks(result.dns) ?? []) {
    const severity = severityFor(ch.rating);
    if (!severity) continue;
    findings.push({ id: `email:${domain}/${slug(ch.name)}`, scope: 'site', severity, title: `${ch.name}: ${ch.detail}`, detail: ch.detail, hint: `peep scan ${domain} --only dns` });
  }

  return findings;
}
