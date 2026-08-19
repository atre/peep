#!/usr/bin/env node

import { parseArgs, printHelp, printVersion } from './cli.js';
import { loadConfig } from './config.js';
import { loadFleetFile } from './fleet-config.js';
import { cmdScan } from './commands/scan.js';
import { cmdFleet } from './commands/fleet.js';
import { cmdCorrelate } from './commands/correlate.js';
import { cmdClassify } from './commands/classify.js';
import { cmdReport } from './commands/report.js';
import { cmdDiff } from './commands/diff.js';
import { cmdCheck } from './commands/check.js';
import { normalizeDomain, strippedPath } from './utils.js';
import { installDnsOverride } from './resolver.js';

async function main(): Promise<void> {
  const { command, domains, flags } = parseArgs(process.argv);
  const fleetFile = loadFleetFile(flags.fleet ? String(flags.fleet) : undefined);
  const config = loadConfig(flags.config ? String(flags.config) : undefined, fleetFile);

  // fleet.yaml `pages` becomes the default --pages routes for scan/check/report
  // when the user didn't pass --pages explicitly — --pages always wins.
  if (!flags.pages && fleetFile?.pages.length) {
    flags.pages = fleetFile.pages.join(',');
  }

  // Normalize all user-supplied domain inputs
  const normalizedDomains = domains.map(normalizeDomain);

  // Honor an explicit http:// target (LAN IP, pre-TLS staging): every scanner
  // fetch uses this scheme instead of assuming https. Only when ALL inputs are
  // explicitly http — mixed-scheme multi-domain scans keep the https default.
  if (domains.length > 0 && domains.every((d) => /^http:\/\//i.test(d))) {
    config.scanning.scheme = 'http';
    console.error('Note: explicit http:// target — scanning over plain HTTP.');
  }

  // --dns <server>: pin the dns scanner's own queries to this server, and give
  // every fetch()/tls.connect()-based scanner (http, tls, robots, assets, ...)
  // the same fallback when the OS resolver disagrees with it. Installed once,
  // for the whole process, regardless of command — see src/resolver.ts for why
  // this is the one fix that makes every scanner resolve through the same path.
  if (typeof flags.dns === 'string' && flags.dns.length > 0) {
    config.scanning.dnsServer = flags.dns;
  }
  installDnsOverride(config.scanning.dnsServer);

  // --lang <xx>: Accept-Language to send. Default (unset) sends none at all —
  // matches Googlebot, avoids skewing a locale-default site toward EN.
  if (typeof flags.lang === 'string' && flags.lang.length > 0) {
    config.scanning.acceptLanguage = flags.lang;
  }

  // --host <domain>: TLS SNI + HTTP Host header override — the scan still
  // connects to the literal target URL/domain, only what's presented as
  // SNI/Host changes. Independent of the explicit http:// skip logic above:
  // usable on a normal https scan (e.g. a preview URL scanned as if it were
  // the real production domain).
  if (typeof flags.host === 'string' && flags.host.length > 0) {
    config.scanning.hostOverride = flags.host;
  }

  // Warn when a path/query/fragment is silently dropped — peep audits the apex
  // only, so scanning "example.com/de" would otherwise return apex data mislabeled
  // as a /de audit. (stderr, so JSON output on stdout stays clean.)
  if (command !== 'diff') { // diff's positionals are files, not domains
    domains.forEach((raw, i) => {
      const path = strippedPath(raw);
      if (path) {
        console.error(
          `Note: "${raw}" includes a path ("${path}") — peep scans the apex ${normalizedDomains[i]}. ` +
          `To audit that route, pass it via --pages ${path}.`,
        );
      }
    });
  }

  switch (command) {
    case 'scan':
      if (normalizedDomains.length === 0) {
        console.error('Usage: peep scan <domain> [domain...]\n');
        process.exit(1);
      }
      await cmdScan(normalizedDomains, config, flags);
      break;

    case 'fleet':
      await cmdFleet(config, flags);
      break;

    case 'correlate':
      await cmdCorrelate(normalizedDomains, config, flags);
      break;

    case 'classify':
      await cmdClassify(normalizedDomains, config, flags);
      break;

    case 'report':
      await cmdReport(normalizedDomains, config, flags);
      break;

    case 'diff':
      // Positionals as parsed (flag values already consumed) — the old
      // argv filter would have taken `-o report.json`'s value as a file.
      await cmdDiff(domains[0] ?? '', domains[1] ?? '', flags);
      break;

    case 'check':
      if (normalizedDomains.length === 0) {
        console.error('Usage: peep check <domain> [--cluster clean|adult]\n');
        process.exit(1);
      }
      await cmdCheck(normalizedDomains[0], config, flags);
      break;

    case 'version':
      printVersion();
      break;

    case 'help':
    default:
      printHelp();
      break;
  }
}

main().catch((err) => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
