import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ScanResult, CorrelationReport, DiffReport, DiffEntry, Severity } from '../types.js';
import { c } from '../utils.js';

const CHANGE_TYPES = new Set<DiffEntry['type']>(['analytics_change', 'noindex_change', 'adult_score_change', 'score_change', 'page_change']);

export interface DiffInput {
  // Could be a single scan, array of scans, or a correlation report
  scans?: ScanResult[];
  correlation?: CorrelationReport;
  // Or a flat scan result
  domain?: string;
}

/** Compare two loaded inputs into a DiffReport. Pure (no I/O) so it can be unit-tested. */
export function buildDiff(a: DiffInput, b: DiffInput, fileA: string, fileB: string): DiffReport {
  const changes: DiffEntry[] = [];

  const scansA = a.scans ?? [];
  const scansB = b.scans ?? [];

  const domainsA = new Set(scansA.map((s) => s.domain));
  const domainsB = new Set(scansB.map((s) => s.domain));
  const mapA = new Map(scansA.map((s) => [s.domain, s]));
  const mapB = new Map(scansB.map((s) => [s.domain, s]));

  // New domains
  for (const d of domainsB) {
    if (!domainsA.has(d)) {
      changes.push({ type: 'new_domain', domain: d, detail: `New domain: ${d}` });
    }
  }

  // Removed domains
  for (const d of domainsA) {
    if (!domainsB.has(d)) {
      changes.push({ type: 'removed_domain', domain: d, detail: `Removed domain: ${d}` });
    }
  }

  // Per-domain diffs
  for (const domain of domainsB) {
    if (!domainsA.has(domain)) continue;
    const sa = mapA.get(domain)!;
    const sb = mapB.get(domain)!;

    // noindex change
    if (sa.isNoindex !== sb.isNoindex) {
      if (sa.isNoindex && !sb.isNoindex) {
        changes.push({ type: 'noindex_change', domain, detail: `${domain}: NOINDEX → LIVE (now indexable)` });
      } else {
        changes.push({ type: 'noindex_change', domain, detail: `${domain}: LIVE → NOINDEX (now blocked)` });
      }
    }

    // Adult score change
    const scoreA = sa.content?.adultScore ?? 0;
    const scoreB = sb.content?.adultScore ?? 0;
    if (Math.abs(scoreA - scoreB) >= 10) {
      changes.push({
        type: 'adult_score_change',
        domain,
        detail: `${domain}: adult score ${scoreA} → ${scoreB}${scoreB > scoreA ? ' (increased)' : ' (decreased)'}`,
      });
    }

    // Analytics changes (GA4, AdSense, GTM)
    diffIdSet(changes, domain, 'GA4', sa.analytics?.ga4, sb.analytics?.ga4);
    diffIdSet(changes, domain, 'AdSense', sa.analytics?.adsense, sb.analytics?.adsense);
    diffIdSet(changes, domain, 'GTM', sa.analytics?.gtm, sb.analytics?.gtm);

    // Score drift (security headers, SEO) — the deploy-to-deploy regressions a
    // baseline exists to catch. Volatile fields (timestamps, timing, asset
    // hashes of per-build chunks) are deliberately never compared.
    diffScore(changes, domain, 'security score', sa.security?.score, sb.security?.score);
    diffScore(changes, domain, 'SEO score', sa.seo?.score, sb.seo?.score);
    diffFailingChecks(changes, domain, '', sa.seo?.checks, sb.seo?.checks);

    // Per-page audits (--pages routes): a page that lost its og:image or
    // flipped to noindex between deploys shows up here.
    const pagesA = new Map((sa.pageAudits ?? []).map((p) => [p.route, p]));
    const pagesB = new Map((sb.pageAudits ?? []).map((p) => [p.route, p]));
    for (const [route, pb] of pagesB) {
      const pa = pagesA.get(route);
      if (!pa) continue; // route not in baseline — nothing to compare against
      if (pa.ok !== pb.ok) {
        changes.push({ type: 'page_change', domain, detail: `${domain}${route}: ${pa.ok ? 'OK' : 'unreachable'} → ${pb.ok ? 'OK' : `unreachable (HTTP ${pb.statusCode ?? '?'})`}` });
        continue;
      }
      if (pa.isNoindex !== pb.isNoindex) {
        changes.push({ type: 'page_change', domain, detail: `${domain}${route}: ${pa.isNoindex ? 'NOINDEX → indexable' : 'indexable → NOINDEX'}` });
      }
      if ((pa.canonicalUrl ?? null) !== (pb.canonicalUrl ?? null)) {
        changes.push({ type: 'page_change', domain, detail: `${domain}${route}: canonical ${pa.canonicalUrl ?? '(none)'} → ${pb.canonicalUrl ?? '(none)'}` });
      }
      diffScore(changes, domain, `${route} SEO score`, pa.seoScore, pb.seoScore, 'page_change');
      diffFailingChecks(changes, domain, route, pa.seoIssues, pb.seoIssues, 'page_change');
    }
  }

  // Correlation findings diff
  const findingsA = a.correlation?.findings ?? [];
  const findingsB = b.correlation?.findings ?? [];

  const fingerprintFinding = (f: { type: string; domains: string[]; detail: string }) =>
    `${f.type}:${[...f.domains].sort().join(',')}:${f.detail}`;

  const setA = new Set(findingsA.map(fingerprintFinding));
  const setB = new Set(findingsB.map(fingerprintFinding));

  for (const f of findingsB) {
    if (!setA.has(fingerprintFinding(f))) {
      changes.push({
        type: 'new_finding',
        detail: `NEW: [${f.severity.toUpperCase()}] ${f.detail} (${f.domains.join(', ')})`,
        severity: f.severity as Severity,
      });
    }
  }

  for (const f of findingsA) {
    if (!setB.has(fingerprintFinding(f))) {
      changes.push({
        type: 'resolved_finding',
        detail: `RESOLVED: [${f.severity.toUpperCase()}] ${f.detail} (${f.domains.join(', ')})`,
        severity: f.severity as Severity,
      });
    }
  }

  const summary = {
    added: changes.filter((ch) => ch.type === 'new_domain' || ch.type === 'new_finding').length,
    removed: changes.filter((ch) => ch.type === 'removed_domain' || ch.type === 'resolved_finding').length,
    changed: changes.filter((ch) => CHANGE_TYPES.has(ch.type)).length,
  };

  return { fileA, fileB, timestamp: new Date().toISOString(), changes, summary };
}

function diffScore(
  changes: DiffEntry[],
  domain: string,
  label: string,
  a: number | null | undefined,
  b: number | null | undefined,
  type: DiffEntry['type'] = 'score_change',
): void {
  if (a == null || b == null || a === b) return;
  changes.push({
    type,
    domain,
    detail: `${domain}: ${label} ${a} → ${b}${b < a ? ' (regressed)' : ' (improved)'}`,
  });
}

/**
 * Compare the set of non-good SEO checks by name. Only the failing set is
 * compared (not detail text) so a title that changed wording but stayed
 * "good" doesn't register — while "Open Graph: good → warning" does.
 */
function diffFailingChecks(
  changes: DiffEntry[],
  domain: string,
  route: string,
  checksA: Array<{ name: string; rating: string; detail: string }> | undefined,
  checksB: Array<{ name: string; rating: string; detail: string }> | undefined,
  type: DiffEntry['type'] = 'score_change',
): void {
  if (!checksA || !checksB) return;
  const failA = new Map(checksA.filter((ch) => ch.rating !== 'good').map((ch) => [ch.name, ch]));
  const failB = new Map(checksB.filter((ch) => ch.rating !== 'good').map((ch) => [ch.name, ch]));
  const where = `${domain}${route}`;
  for (const [name, ch] of failB) {
    if (!failA.has(name)) changes.push({ type, domain, detail: `${where}: SEO check now failing — ${name}: ${ch.detail}` });
  }
  for (const name of failA.keys()) {
    if (!failB.has(name)) changes.push({ type, domain, detail: `${where}: SEO check fixed — ${name}` });
  }
}

/** Emit added/removed entries for a single analytics ID set (e.g. GA4) on a domain. */
function diffIdSet(
  changes: DiffEntry[],
  domain: string,
  label: string,
  idsA: string[] | undefined,
  idsB: string[] | undefined,
): void {
  const a = new Set(idsA ?? []);
  const b = new Set(idsB ?? []);
  for (const id of b) {
    if (!a.has(id)) changes.push({ type: 'analytics_change', domain, detail: `${domain}: new ${label} ID: ${id}` });
  }
  for (const id of a) {
    if (!b.has(id)) changes.push({ type: 'analytics_change', domain, detail: `${domain}: removed ${label} ID: ${id}` });
  }
}

function loadFile(filePath: string): DiffInput {
  const fullPath = resolve(process.cwd(), filePath);
  const raw = readFileSync(fullPath, 'utf-8');
  const parsed = JSON.parse(raw);

  // Detect format
  if (Array.isArray(parsed)) {
    // Array of scan results
    return { scans: parsed as ScanResult[] };
  }
  if (parsed.scans && parsed.correlation) {
    // Full report
    return { scans: parsed.scans as ScanResult[], correlation: parsed.correlation as CorrelationReport };
  }
  if (parsed.domain && parsed.timestamp) {
    // Single scan result
    return { scans: [parsed as ScanResult] };
  }
  if (parsed.findings && parsed.domains) {
    // Correlation report only
    return { correlation: parsed as CorrelationReport };
  }
  // Fallback: treat as array
  return { scans: Array.isArray(parsed) ? parsed : [parsed] };
}

export async function cmdDiff(
  file1: string,
  file2: string,
  flags: Record<string, string | boolean>,
): Promise<void> {
  const format = flags.format === 'json' || flags.j === true ? 'json' : 'text';

  if (!file1 || !file2) {
    console.error('Usage: peep diff <file1.json> <file2.json>');
    process.exit(1);
  }

  let a: DiffInput;
  let b: DiffInput;

  try {
    a = loadFile(file1);
  } catch (e) {
    console.error(`Failed to read ${file1}: ${(e as Error).message}`);
    process.exit(1);
  }

  try {
    b = loadFile(file2);
  } catch (e) {
    console.error(`Failed to read ${file2}: ${(e as Error).message}`);
    process.exit(1);
  }

  const report = buildDiff(a, b, file1, file2);
  const { changes, summary } = report;

  if (format === 'json') {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  // Text output
  console.log(`\n${c('bold', 'PEEP Diff Report')}`);
  console.log(`  ${file1}  →  ${file2}`);
  console.log(`  ${changes.length} change(s): +${summary.added} added, -${summary.removed} removed, ~${summary.changed} changed\n`);

  if (changes.length === 0) {
    console.log(c('green', '  No differences found.'));
    return;
  }

  // Group by type
  const newFindings = changes.filter((ch) => ch.type === 'new_finding');
  const resolved = changes.filter((ch) => ch.type === 'resolved_finding');
  const domainChanges = changes.filter((ch) => ch.type === 'new_domain' || ch.type === 'removed_domain');
  const other = changes.filter((ch) => CHANGE_TYPES.has(ch.type));

  if (newFindings.length > 0) {
    console.log(c('red', `  New Findings (${newFindings.length})`));
    for (const ch of newFindings) {
      console.log(`    ${ch.detail}`);
    }
    console.log('');
  }

  if (resolved.length > 0) {
    console.log(c('green', `  Resolved Findings (${resolved.length})`));
    for (const ch of resolved) {
      console.log(`    ${ch.detail}`);
    }
    console.log('');
  }

  if (domainChanges.length > 0) {
    console.log(c('cyan', `  Domain Changes (${domainChanges.length})`));
    for (const ch of domainChanges) {
      console.log(`    ${ch.detail}`);
    }
    console.log('');
  }

  if (other.length > 0) {
    console.log(c('yellow', `  Other Changes (${other.length})`));
    for (const ch of other) {
      console.log(`    ${ch.detail}`);
    }
    console.log('');
  }
}
