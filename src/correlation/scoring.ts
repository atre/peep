import type { CorrelationFinding, CorrelationReport, ScanResult } from '../types.js';

export function buildReport(
  results: ScanResult[],
  findings: CorrelationFinding[],
  matrix: Record<string, Record<string, number>>,
): CorrelationReport {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    summary[f.severity]++;
  }

  // Overall fleet isolation score (0-100, higher = better isolated)
  const score = computeIsolationScore(findings, results.length);

  return {
    timestamp: new Date().toISOString(),
    domains: results.map((r) => r.domain),
    findings,
    score,
    matrix,
    summary,
  };
}

// Fleet-wide finding types are already deduplicated and represent fleet-level problems.
// Their penalties apply at full weight regardless of fleet size.
// Pairwise findings scale with C(n,2) — normalize them so larger fleets don't auto-zero.
const FLEET_WIDE_TYPES = new Set([
  'fleet-wide-tracking-id',
  'cross-cluster-adult',
  'cross-cluster-adult-ads',
  'cross-cluster-adult-affiliate',
  'shared-google-verification',
  'shared-ms-verification',
  'shared-facebook-verification',
  'shared-ads-txt-pubid',
  'shared-affiliate-redirect-path',
]);

const SEVERITY_PENALTY: Record<string, number> = { critical: 25, high: 10, medium: 5, low: 2 };

// Commodity signals shared by "any Cloudflare + Astro" site (shared NS/MX, popular
// webfonts, framework sitemap/robots templates, generic generator/server headers).
// They're real but weak — without discounting them, a fleet of unrelated brands on
// the same stack accrues enough penalty to drown out genuine links. We keep the
// findings (still informative) but scale their score impact down.
const COMMODITY_TYPES = new Set([
  'shared-nameservers',
  'shared-mx',
  'shared-fonts',
  'shared-generator',
  'shared-robots',
  'shared-cookies',
  'shared-head-structure',
  'shared-css-hash',
  'shared-js-hash-cdn',
  'shared-sitemap-structure',
  'shared-sitemap-hash',
  'shared-ip-same-cluster',
]);
const COMMODITY_DISCOUNT = 0.4;

function computeIsolationScore(findings: CorrelationFinding[], domainCount: number): number {
  let fleetPenalty = 0;
  let pairwisePenalty = 0;

  for (const f of findings) {
    let weight = SEVERITY_PENALTY[f.severity] ?? 0;
    if (COMMODITY_TYPES.has(f.type)) weight = Math.max(1, Math.round(weight * COMMODITY_DISCOUNT));
    if (FLEET_WIDE_TYPES.has(f.type)) {
      fleetPenalty += weight;
    } else {
      pairwisePenalty += weight;
    }
  }

  // Normalize pairwise penalties by pair count so large fleets don't automatically score 0.
  // For 2-3 domains the normalizer is 1 (unchanged). For 9 domains (36 pairs) it's 12.
  const pairs = Math.max(1, domainCount * (domainCount - 1) / 2);
  const normalizer = Math.max(1, Math.ceil(pairs / 3));

  return Math.max(0, 100 - fleetPenalty - Math.round(pairwisePenalty / normalizer));
}

// Commodity pairwise traits that go fleet-wide turn into N×(N-1)/2 identical lines
// (45 for a 10-site fleet). In the human report we collapse each such trait to one
// rollup line; the full pairwise set stays in report.findings (JSON) and the matrix.
const COMMODITY_COLLAPSE_TYPES = new Set([
  'shared-fonts',
  'shared-mx',
  'shared-nameservers',
  'shared-form-provider',
  'shared-sitemap-structure',
  'shared-sitemap-hash',
  'shared-js-hash-cdn',
  'shared-robots',
  'shared-cookies',
  'shared-ip-same-cluster',
]);

// Pairwise type → its fleet-wide rollup. When the rollup already covers a group's
// domains, the pairwise lines are dropped entirely (the rollup line says it all).
const ROLLUP_FOR: Record<string, string> = {
  'shared-form-provider': 'fleet-wide-form-provider',
};

const COLLAPSE_MIN_PAIRS = 3;
const SEV_RANK: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0 };

/**
 * Replace redundant commodity pairwise findings with a single rollup line for the
 * human report. Groups by (type, detail) — identical detail means the same shared
 * value across many pairs. A group is collapsed when it spans ≥3 pairs, or dropped
 * outright when a fleet-wide rollup already covers its domains. Non-commodity and
 * small (1–2 pair) groups pass through unchanged.
 */
export function collapseCommodityPairwise(findings: CorrelationFinding[]): CorrelationFinding[] {
  const groups = new Map<string, CorrelationFinding[]>();
  for (const f of findings) {
    if (!COMMODITY_COLLAPSE_TYPES.has(f.type)) continue;
    const key = `${f.type}\n${f.detail}`;
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(f);
  }

  const rollupDomains = new Map<string, Set<string>[]>();
  const rollupTypes = new Set(Object.values(ROLLUP_FOR));
  for (const f of findings) {
    if (!rollupTypes.has(f.type)) continue;
    (rollupDomains.get(f.type) ?? rollupDomains.set(f.type, []).get(f.type)!).push(new Set(f.domains));
  }
  const coveredByRollup = (type: string, domains: string[]): boolean => {
    const sets = rollupDomains.get(ROLLUP_FOR[type] ?? '');
    return sets ? sets.some((s) => domains.every((d) => s.has(d))) : false;
  };

  const emitted = new Set<string>();
  const out: CorrelationFinding[] = [];
  for (const f of findings) {
    if (!COMMODITY_COLLAPSE_TYPES.has(f.type)) { out.push(f); continue; }
    const key = `${f.type}\n${f.detail}`;
    if (emitted.has(key)) continue;
    emitted.add(key);
    const group = groups.get(key)!;
    const union = [...new Set(group.flatMap((g) => g.domains))].sort();

    if (coveredByRollup(f.type, union)) continue;
    if (group.length < COLLAPSE_MIN_PAIRS) { out.push(...group); continue; }

    const severity = group.reduce<CorrelationFinding['severity']>(
      (m, g) => (SEV_RANK[g.severity] > SEV_RANK[m] ? g.severity : m), group[0].severity);
    out.push({
      type: f.type,
      severity,
      domains: union,
      detail: f.detail,
      evidence: `Fleet-wide commodity trait — shared across ${union.length} sites (collapsed from ${group.length} pairs)`,
    });
  }
  return out;
}

export function formatReportText(report: CorrelationReport): string {
  const lines: string[] = [];

  lines.push('PEEP Fleet Correlation Report');
  lines.push('='.repeat(50));
  lines.push(`Scan time: ${report.timestamp}`);
  lines.push(`Domains: ${report.domains.length}`);
  lines.push(`Isolation score: ${report.score}/100`);
  lines.push('');

  // Summary
  lines.push('Findings Summary');
  lines.push('-'.repeat(30));
  if (report.summary.critical > 0) lines.push(`  CRITICAL: ${report.summary.critical}`);
  if (report.summary.high > 0) lines.push(`  HIGH:     ${report.summary.high}`);
  if (report.summary.medium > 0) lines.push(`  MEDIUM:   ${report.summary.medium}`);
  if (report.summary.low > 0) lines.push(`  LOW:      ${report.summary.low}`);
  if (Object.values(report.summary).every((v) => v === 0)) {
    lines.push('  No correlation findings. Fleet looks clean.');
  }
  lines.push('');

  // Findings by severity — collapse fleet-wide commodity pairwise spam for display.
  const displayFindings = collapseCommodityPairwise(report.findings);
  const collapsed = report.findings.length - displayFindings.length;
  if (collapsed > 0) {
    lines.push(`(${collapsed} redundant pairwise line(s) rolled up — full pairwise set in JSON output)`);
    lines.push('');
  }
  const grouped = groupBySeverity(displayFindings);
  for (const severity of ['critical', 'high', 'medium', 'low'] as const) {
    const items = grouped[severity];
    if (!items?.length) continue;

    lines.push(`${severity.toUpperCase()} Findings`);
    lines.push('-'.repeat(30));
    for (const f of items) {
      lines.push(`  [${f.type}] ${f.detail}`);
      lines.push(`    Domains: ${f.domains.join(', ')}`);
      lines.push(`    Evidence: ${f.evidence}`);
      lines.push('');
    }
  }

  // Similarity matrix (if manageable size)
  if (report.domains.length <= 20) {
    lines.push('Similarity Matrix');
    lines.push('-'.repeat(30));
    const maxLen = Math.max(...report.domains.map((d) => d.length));
    const header = ' '.repeat(maxLen + 2) + report.domains.map((d) => d.slice(0, 12).padStart(13)).join('');
    lines.push(header);
    for (const d1 of report.domains) {
      const row = d1.padEnd(maxLen + 2) + report.domains
        .map((d2) => {
          const val = report.matrix[d1]?.[d2] ?? 0;
          return String(val).padStart(13);
        })
        .join('');
      lines.push(row);
    }
    lines.push('');
  }

  return lines.join('\n');
}

export function formatReportJson(report: CorrelationReport): string {
  return JSON.stringify(report, null, 2);
}

function groupBySeverity(
  findings: CorrelationFinding[],
): Record<string, CorrelationFinding[]> {
  const groups: Record<string, CorrelationFinding[]> = {};
  for (const f of findings) {
    if (!groups[f.severity]) groups[f.severity] = [];
    groups[f.severity].push(f);
  }
  return groups;
}
