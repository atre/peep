import { scanDomain } from '../scanners/index.js';
import { mapConcurrent } from '../concurrency.js';
import type { PeepConfig, ScanResult, OutputFormat } from '../types.js';
import { c, formatDuration, getCluster, resolveScanningConfig, isAdultCluster } from '../utils.js';

export async function cmdFleet(
  config: PeepConfig,
  flags: Record<string, string | boolean>,
): Promise<ScanResult[]> {
  const format = (flags.format as OutputFormat) || 'text';
  const domains = config.fleet.domains;
  const skipWhois = flags['skip-whois'] === true;
  const skipAssets = flags['skip-assets'] === true;
  const scanConfig = resolveScanningConfig(flags, config.scanning);
  const quiet = flags.quiet === true;
  const only = flags.only ? String(flags.only).split(',') : config.scanning.only;

  if (domains.length === 0) {
    console.error('No domains specified. Add domains to .peeprc or pass them as arguments.');
    process.exit(1);
  }

  if (format === 'text' && !quiet) {
    console.error(`\nScanning fleet: ${c('cyan', String(domains.length))} domains (concurrency: ${config.scanning.concurrency})\n`);
  }

  let completed = 0;
  const start = Date.now();

  // For large fleets, add per-domain delay to avoid WHOIS/DNS rate limits
  const delayOpts = domains.length > 5 ? { delayMs: 200, jitterMs: 300 } : undefined;

  const results = await mapConcurrent(domains, config.scanning.concurrency, async (domain) => {
    const result = await scanDomain(domain, {
      config: scanConfig,
      adultScoreThreshold: config.thresholds.adultScore,
      skipWhois,
      skipAssets,
      only,
    });

    completed++;
    if (format === 'text' && !quiet) {
      const pct = Math.round((completed / domains.length) * 100);
      const errStr = result.errors.length > 0 ? c('yellow', ` (${result.errors.length} err)`) : '';
      const adultStr = result.content?.isAdult ? c('red', ' [ADULT]') : '';
      const noindexStr = result.isNoindex ? c('yellow', ' [NOINDEX]') : '';
      console.error(`  [${String(pct).padStart(3)}%] ${domain.padEnd(30)} ${formatDuration(result.duration)}${errStr}${adultStr}${noindexStr}`);
    }

    return result;
  }, delayOpts);

  const totalTime = Date.now() - start;

  if (format === 'text') {
    if (!quiet) {
      console.error(`\nFleet scan complete: ${domains.length} domains in ${formatDuration(totalTime)}`);
    }
    const errCount = results.reduce((sum, r) => sum + r.errors.length, 0);
    if (errCount > 0) console.error(`  ${c('yellow', `${errCount} total errors across fleet`)}`);

    const adultOnClean = results.filter((r) => {
      if (!r.content?.isAdult) return false;
      const cluster = getCluster(r.domain, config.fleet.clusters);
      return cluster && !isAdultCluster(cluster);
    });
    if (adultOnClean.length > 0) {
      console.error(`  ${c('red', `${adultOnClean.length} clean-cluster sites with adult content!`)}`);
    }

    const noindexSites = results.filter((r) => r.isNoindex);
    if (noindexSites.length > 0) {
      const label = quiet ? '' : '  ';
      console.error(`${label}${c('yellow', `${noindexSites.length} site(s) still NOINDEX (placeholder/staging):`)}`);
      for (const r of noindexSites) {
        console.error(`    ${r.domain}`);
      }
    }
  } else if (format === 'json') {
    console.log(JSON.stringify(results, null, 2));
  }

  return results;
}

