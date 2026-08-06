import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { ScanResult, CorrelationReport, DiffReport, DiffEntry, Severity } from '../types.js';
import { c } from '../utils.js';

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
    changed: changes.filter((ch) => ch.type === 'analytics_change' || ch.type === 'noindex_change' || ch.type === 'adult_score_change').length,
  };

  return { fileA, fileB, timestamp: new Date().toISOString(), changes, summary };
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
  const other = changes.filter((ch) => ch.type === 'analytics_change' || ch.type === 'noindex_change' || ch.type === 'adult_score_change');

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
