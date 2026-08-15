import { scanDomain, validateScannerNames, expandScanners, SELECTABLE_SCANNERS } from '../scanners/index.js';
import type { PeepConfig, CheckResult, ScanResult } from '../types.js';
import { c, getCluster, scoreColor, isAdultCluster } from '../utils.js';

const DEFAULT_SECURITY_THRESHOLD = 50;

export interface CheckGateOptions {
  clusterOverride: string | null;
  securityThreshold: number;
  requireSecurityTxt: boolean;
  /** --expect noindex / --prelaunch: converts an otherwise-failing noindex into
   *  a PASS annotated in `notes`. Must be threaded in explicitly per call — never
   *  defaulted from config, or a forgotten noindex after launch would go silent. */
  expectNoindex: boolean;
  /** Scanner subset the scan was run with (`--only`). Gates that depend on a
   *  scanner that was deliberately not run are skipped and noted, not failed. */
  only?: string[];
}

export interface CheckGateResult {
  clusterName: string | null;
  failures: string[];
  notes: string[];
}

/**
 * Evaluate a completed scan against the deploy-gate rules. Pure (no I/O, no
 * process.exit) so it can be unit-tested without a real scan — see buildDiff()
 * in commands/diff.ts for the same pattern.
 */
export function evaluateCheck(
  domain: string,
  scanResult: ScanResult,
  clusters: Record<string, string[]>,
  opts: CheckGateOptions,
): CheckGateResult {
  const failures: string[] = [];
  const notes: string[] = [];

  const clusterName = opts.clusterOverride ?? getCluster(domain, clusters);
  const isCleanCluster = clusterName && !isAdultCluster(clusterName);

  // Check 1: no adult signals on clean cluster
  if (isCleanCluster && scanResult.content?.isAdult) {
    failures.push(
      `Adult content detected on clean cluster "${clusterName}" (score: ${scanResult.content.adultScore})`,
    );
  }

  // Check 2: noindex NOT set (site must be live and indexable) — unless the
  // caller explicitly declared this a pre-launch scan (--expect noindex /
  // --prelaunch), in which case a noindex is the correct, intentional state
  // and converts to a PASS instead of a failure.
  if (scanResult.isNoindex) {
    if (opts.expectNoindex) {
      notes.push('noindex (declared pre-launch)');
    } else {
      failures.push(
        `Site is NOINDEX — remove noindex meta tag / X-Robots-Tag before deploying`,
      );
    }
  }

  const selected = opts.only ? new Set(expandScanners(opts.only)) : null;
  const ran = (name: string) => !selected || selected.has(name);

  // Check 3: security score >= threshold
  if (ran('security')) {
    const secScore = scanResult.security?.score ?? 0;
    if (secScore < opts.securityThreshold) {
      failures.push(
        `Security score ${secScore}/100 is below threshold ${opts.securityThreshold} — fix security headers`,
      );
    }
  } else {
    notes.push('security score not evaluated (excluded by --only)');
  }

  // Check 4: security.txt required
  if (opts.requireSecurityTxt) {
    if (!ran('robots')) {
      notes.push('security.txt not checked (robots excluded by --only)');
    } else if (!scanResult.robots?.securityTxt) {
      failures.push(
        `security.txt not found — required by --require-security-txt`,
      );
    }
  }

  // Check 5: no critical scan errors
  const criticalErrors = scanResult.errors.filter((e) =>
    ['dns', 'http', 'tls'].includes(e.scanner),
  );
  for (const e of criticalErrors) {
    failures.push(`Critical scanner error [${e.scanner}]: ${e.error}`);
  }

  return { clusterName, failures, notes };
}

export async function cmdCheck(
  domain: string,
  config: PeepConfig,
  flags: Record<string, string | boolean>,
): Promise<void> {
  const clusterOverride = flags.cluster ? String(flags.cluster) : null;
  const rawScore = typeof flags['min-score'] === 'string' ? Number(flags['min-score']) : NaN;
  const securityThreshold = Number.isFinite(rawScore) ? rawScore : DEFAULT_SECURITY_THRESHOLD;
  const requireSecurityTxt = flags['require-security-txt'] === true;
  const format = flags.format === 'json' || flags.j === true ? 'json' : 'text';
  // Explicit, per-invocation escape hatch for the deliberate pre-launch pattern
  // (site public for a payment-provider review but kept noindex until go-live).
  // Deliberately NOT readable from .peeprc — a config default could mask a
  // forgotten noindex after the site actually launches.
  const expectNoindex = flags.prelaunch === true || flags['allow-noindex'] === true || String(flags.expect ?? '').toLowerCase() === 'noindex';
  // --only narrows the gate's scan the same way it narrows `scan`. WHOIS is
  // skipped by default (slow), but an explicit `--only whois` asks for it.
  const only = flags.only ? String(flags.only).split(',') : undefined;
  if (only) {
    const unknown = validateScannerNames(only);
    if (unknown.length > 0) {
      console.error(`Warning: unknown scanner(s) in --only: ${unknown.join(', ')}. Known: ${SELECTABLE_SCANNERS.join(', ')}`);
    }
  }
  const skipWhois = !(only?.includes('whois') ?? false);

  if (format === 'text') {
    process.stdout.write(`Checking ${c('cyan', domain)}...`);
  }

  const scanResult = await scanDomain(domain, {
    config: config.scanning,
    adultScoreThreshold: config.thresholds.adultScore,
    skipWhois,
    skipAssets: true,
    only,
  });

  if (format === 'text') {
    console.log(' done');
  }

  const { clusterName, failures, notes } = evaluateCheck(domain, scanResult, config.fleet.clusters, {
    clusterOverride,
    securityThreshold,
    requireSecurityTxt,
    expectNoindex,
    only,
  });
  const secScore = scanResult.security?.score ?? 0;

  const result: CheckResult = {
    domain,
    passed: failures.length === 0,
    failures,
    notes,
    scanResult,
  };

  if (format === 'json') {
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.passed ? 0 : 1);
    return;
  }

  // Text output
  console.log('');
  if (result.passed) {
    console.log(c('green', `  PASS: ${domain} is ready to deploy`));
  } else {
    console.log(c('red', `  FAIL: ${domain} has ${failures.length} issue(s):`));
    for (const f of failures) {
      console.log(`    ${c('red', '✗')} ${f}`);
    }
  }

  // Show key metrics
  console.log('');
  const adultStatus = scanResult.content?.isAdult ? c('red', 'ADULT') : c('green', 'CLEAN');
  const indexStatus = scanResult.isNoindex
    ? (expectNoindex ? c('green', 'NOINDEX (pre-launch, expected)') : c('yellow', 'NOINDEX'))
    : c('green', 'LIVE');
  const secStatus = scanResult.security
    ? `${c(scoreColor(secScore, securityThreshold), String(secScore))}/100`
    : c('dim', 'n/a');
  console.log(`  Content: ${adultStatus}  |  Index: ${indexStatus}  |  Security: ${secStatus}`);
  if (clusterName) console.log(`  Cluster: ${clusterName}`);
  if (notes.length > 0) {
    for (const n of notes) console.log(`  ${c('dim', `note: ${n}`)}`);
  }
  console.log('');

  process.exit(result.passed ? 0 : 1);
}
