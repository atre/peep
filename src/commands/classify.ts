import { scanDomain } from '../scanners/index.js';
import { mapConcurrent } from '../concurrency.js';
import type { PeepConfig, OutputFormat } from '../types.js';
import { c, severityColor, getCluster, writeOutputFile } from '../utils.js';

export async function cmdClassify(
  domains: string[],
  config: PeepConfig,
  flags: Record<string, string | boolean>,
): Promise<void> {
  const format = (flags.format as OutputFormat) || 'text';
  const outFile = flags.out ? String(flags.out) : null;
  const targetDomains = domains.length > 0 ? domains : config.fleet.domains;

  if (targetDomains.length === 0) {
    console.error('No domains specified. Pass domains as arguments or configure .peeprc');
    process.exit(1);
  }

  if (format === 'text') {
    console.log(`\nClassifying ${c('cyan', String(targetDomains.length))} domain(s)...\n`);
  }

  const results = await mapConcurrent(targetDomains, config.scanning.concurrency, async (domain) => {
    return scanDomain(domain, {
      config: config.scanning,
      skipWhois: true,
      skipAssets: true,
      only: ['http', 'content', 'analytics'],
    });
  });

  // classify only has a structured (JSON) serialization, used for both --out and -j
  const output = results.map((r) => ({
    domain: r.domain,
    isAdult: r.content?.isAdult ?? false,
    adultScore: r.content?.adultScore ?? 0,
    signals: r.content?.signals ?? [],
    affiliateLinks: r.content?.affiliateLinks ?? [],
    adNetworks: r.content?.adNetworks ?? [],
    cluster: getCluster(r.domain, config.fleet.clusters),
  }));

  if (outFile) {
    if (!outFile.endsWith('.json')) {
      console.error(`Note: 'peep classify --out' writes JSON; ${outFile} will contain JSON.`);
    }
    const full = writeOutputFile(outFile, JSON.stringify(output, null, 2));
    console.error(`\nClassification written to ${c('cyan', full)}`);
  }

  if (format === 'json') {
    console.log(JSON.stringify(output, null, 2));
    return;
  }

  // Text output
  let violations = 0;

  for (const r of results) {
    const cls = r.content;
    if (!cls) {
      console.log(`  ${r.domain.padEnd(30)} ${c('yellow', 'SCAN FAILED')}`);
      continue;
    }

    const cluster = getCluster(r.domain, config.fleet.clusters);
    const isCleanCluster = cluster && !cluster.startsWith('adult');
    const label = cls.isAdult ? c('red', 'ADULT') : c('green', 'CLEAN');
    const scoreStr = `score: ${cls.adultScore}`;
    const clusterStr = cluster ? c('gray', `[${cluster}]`) : '';

    // Flag violations: adult content on clean cluster
    const violation = isCleanCluster && cls.isAdult;
    if (violation) violations++;

    const prefix = violation ? c('red', 'VIOLATION ') : '  ';
    console.log(`${prefix}${r.domain.padEnd(30)} ${label} (${scoreStr}) ${clusterStr}`);

    // Show signals for adult or violations
    if (cls.isAdult || violation) {
      for (const s of cls.signals.slice(0, 5)) {
        const col = severityColor(s.severity);
        console.log(`    ${c(col, `[${s.severity}]`)} ${s.type}: ${s.value}`);
      }
      if (cls.signals.length > 5) {
        console.log(`    ... +${cls.signals.length - 5} more signals`);
      }
    }

    // Show adult affiliates/ads on any site
    const adultAff = cls.affiliateLinks.filter((a) => a.isAdult);
    if (adultAff.length > 0 && isCleanCluster) {
      console.log(`    ${c('red', 'Adult affiliates:')} ${adultAff.map((a) => a.network).join(', ')}`);
    }
    const adultAds = cls.adNetworks.filter((a) => a.isAdult);
    if (adultAds.length > 0 && isCleanCluster) {
      console.log(`    ${c('red', 'Adult ad networks:')} ${adultAds.map((a) => a.name).join(', ')}`);
    }
  }

  console.log('');
  if (violations > 0) {
    console.log(c('red', `${violations} violation(s): adult content detected on clean-cluster sites`));
    process.exit(2);
  } else {
    console.log(c('green', 'No cross-cluster violations detected'));
  }
}

