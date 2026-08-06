import { scanDomain } from '../scanners/index.js';
import { mapConcurrent } from '../concurrency.js';
import { computeCorrelation } from '../correlation/matrix.js';
import { buildReport, formatReportText, formatReportJson } from '../correlation/scoring.js';
import type { PeepConfig, ScanResult } from '../types.js';
import { c, formatDuration, getCluster, parsePagesFlag, writeOutputFile } from '../utils.js';

export async function cmdReport(
  domains: string[],
  config: PeepConfig,
  flags: Record<string, string | boolean>,
): Promise<void> {
  const outFile = flags.out ? String(flags.out) : null;

  // If domains passed as CLI args, use those instead of fleet config
  const effectiveConfig = domains.length > 0
    ? { ...config, fleet: { ...config.fleet, domains } }
    : config;
  const effectiveDomains = effectiveConfig.fleet.domains;

  if (effectiveDomains.length === 0) {
    console.error('No domains specified. Add domains to .peeprc or pass them as arguments.');
    process.exit(1);
  }

  console.log(`\n${c('bold', 'PEEP Full Fleet Audit')}`);
  console.log(`Scanning ${c('cyan', String(effectiveDomains.length))} domains...\n`);

  const start = Date.now();
  let completed = 0;

  // Honor scan-style flags so the audit sees the same signals a standalone scan
  // would — notably --pages, which populates html.formEndpoints and drives the
  // exact shared-endpoint correlation findings.
  const { pages, pageRoutes } = parsePagesFlag(flags);
  const skipWhois = flags['skip-whois'] === true;
  const skipAssets = flags['skip-assets'] === true;
  const only = flags.only ? String(flags.only).split(',') : effectiveConfig.scanning.only;

  const results: ScanResult[] = await mapConcurrent(
    effectiveDomains,
    effectiveConfig.scanning.concurrency,
    async (domain) => {
      const result = await scanDomain(domain, {
        config: effectiveConfig.scanning,
        adultScoreThreshold: effectiveConfig.thresholds.adultScore,
        skipWhois,
        skipAssets,
        only,
        pages,
        pageRoutes,
      });
      completed++;
      const pct = Math.round((completed / effectiveDomains.length) * 100);
      process.stderr.write(`\r  Progress: ${pct}% (${completed}/${effectiveDomains.length})`);
      return result;
    },
  );

  console.error(`\n  Fleet scan: ${formatDuration(Date.now() - start)}\n`);

  // Correlation
  console.error('Computing correlation...');
  const { findings, matrix } = computeCorrelation(results, effectiveConfig.fleet.clusters);
  const report = buildReport(results, findings, matrix);

  // Per-site summary
  console.log(`\n${c('bold', 'Per-Site Summary')}`);
  console.log('-'.repeat(70));
  for (const r of results) {
    const cluster = getCluster(r.domain, config.fleet.clusters) ?? '-';
    const adult = r.content?.isAdult ? c('red', 'ADULT') : c('green', 'CLEAN');
    const score = r.content?.adultScore ?? 0;
    const errCount = r.errors.length;
    const ip = r.dns?.a?.[0] ?? '-';
    const indexStatus = r.isNoindex ? c('yellow', 'NOINDEX') : c('green', 'LIVE');

    console.log(
      `  ${r.domain.padEnd(28)} ${adult.padEnd(20)} ${indexStatus.padEnd(16)} score:${String(score).padStart(3)} ` +
      `IP:${ip.padEnd(16)} cluster:${cluster.padEnd(10)} ` +
      `${errCount > 0 ? c('yellow', `${errCount}err`) : ''}`,
    );
  }

  // Full correlation report
  console.log('');
  console.log(formatReportText(report));

  // Write to file if requested
  if (outFile) {
    const isJson = outFile.endsWith('.json');
    const content = isJson
      ? JSON.stringify({ scans: results, correlation: report }, null, 2)
      : formatReportText(report);
    const fullPath = writeOutputFile(outFile, content);
    console.log(`\nReport written to ${c('cyan', fullPath)}`);
  }

  // Exit code
  if (report.summary.critical > 0) {
    process.exit(2);
  } else if (report.score < config.thresholds.correlationWarning) {
    process.exit(1);
  }
}

