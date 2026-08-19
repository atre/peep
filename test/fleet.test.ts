import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildFleetScanOptions, rollupCheckFailures, formatRollupLine, type FleetCheckResult } from '../src/commands/fleet.js';
import { evaluateCheck, type CheckGateOptions } from '../src/commands/check.js';
import { classifyCheckFailure } from '../src/utils.js';
import { loadConfig } from '../src/config.js';
import type { PeepConfig, ScanResult } from '../src/types.js';

function baseConfig(overrides: Partial<PeepConfig> = {}): PeepConfig {
  const config = loadConfig('/nonexistent/path/that/does/not/exist/.peeprc');
  return { ...config, ...overrides };
}

// Regression: `correlate` (and `fleet`) scan domains via cmdFleet, whose
// ScanOptions previously omitted --pages/--page-routes entirely — unlike scan/
// check/report, which all wire parsePagesFlag() through. That silently capped
// html.formEndpoints at whatever the raw homepage HTML contains, so a shared
// Formspree/Calendly account id living on a crawled /contact or /book page
// (not the homepage) never reached shared-form-endpoint / fleet-wide-form-
// endpoint correlation — only the weaker CSP-provider-level finding fired.
test('buildFleetScanOptions forwards --pages count to scanDomain options', () => {
  const opts = buildFleetScanOptions(baseConfig(), { pages: '5' });
  assert.equal(opts.pages, 5);
  assert.deepEqual(opts.pageRoutes, []);
});

test('buildFleetScanOptions forwards --pages route list to scanDomain options', () => {
  const opts = buildFleetScanOptions(baseConfig(), { pages: '/contact,/book' });
  assert.equal(opts.pages, 0);
  assert.deepEqual(opts.pageRoutes, ['/contact', '/book']);
});

test('buildFleetScanOptions defaults to no crawl when --pages is absent', () => {
  const opts = buildFleetScanOptions(baseConfig(), {});
  assert.equal(opts.pages, 0);
  assert.deepEqual(opts.pageRoutes, []);
});

test('buildFleetScanOptions still forwards skip-whois/skip-assets/only', () => {
  const opts = buildFleetScanOptions(baseConfig(), {
    'skip-whois': true,
    'skip-assets': true,
    only: 'html,analytics',
  });
  assert.equal(opts.skipWhois, true);
  assert.equal(opts.skipAssets, true);
  assert.deepEqual(opts.only, ['html', 'analytics']);
});

// PLAN.md "fleet roll-up": when the same check fails on the same route across
// N fleet domains, the fleet-level summary should print one rolled-up line
// ("same check fails on N/10 domains: <check>") instead of repeating it once
// per domain. rollupCheckFailures()/formatRollupLine() are the pure functions
// cmdFleet's text/JSON output builds on — exercised directly here (no
// network) the same way check.test.ts exercises evaluateCheck() directly.

function gateOpts(over: Partial<CheckGateOptions> = {}): CheckGateOptions {
  return {
    clusterOverride: null,
    securityThreshold: 50,
    requireSecurityTxt: false,
    expectNoindex: false,
    ...over,
  };
}

function scanNoDmarc(domain: string): ScanResult {
  return {
    domain,
    url: `https://${domain}`,
    timestamp: new Date().toISOString(),
    duration: 100,
    isNoindex: false,
    dns: {
      a: [], aaaa: [], mx: [], txt: [], ns: [], cname: [],
      googleVerification: null, microsoftVerification: null, facebookVerification: null,
      spf: { raw: 'v=spf1 -all', includes: [], ip4: [], ip6: [], redirect: null, all: '-all' },
      dmarc: null, // no _dmarc record → "DMARC missing" failure
      caa: [], dkim: [],
    },
    http: null, tls: null, whois: null, html: null, analytics: null, assets: null,
    robots: { robotsTxt: 'x', robotsTxtHash: 'h', sitemapUrls: [], sitemapHash: null, affiliateRedirectPaths: [], adsTxt: null, adsTxtHash: null, adsTxtPubIds: [], securityTxt: null, humansTxt: null },
    content: null,
    security: { score: 80, headers: [], formProviders: [] },
    seo: null, tech: null, errors: [],
  };
}

const presentSecurityTxt = 'Contact: mailto:security@x.com';

// Real evaluateCheck() output for 3 domains, run through the fleet gate
// (--require-email-auth, --require-security-txt): a.com/b.com both lack a
// DMARC record (only DMARC fails — their fix-suggestion text differs, it's
// per-domain, e.g. `_dmarc.a.com` vs `_dmarc.b.com`); c.com has DMARC but
// lacks security.txt (only that fails, and only for c.com).
function fixtureFleetCheckResults(): FleetCheckResult[] {
  const opts = gateOpts({ requireEmailAuth: true, requireSecurityTxt: true });
  const scans: Record<string, ScanResult> = {
    'a.com': { ...scanNoDmarc('a.com'), robots: { ...scanNoDmarc('a.com').robots!, securityTxt: presentSecurityTxt } },
    'b.com': { ...scanNoDmarc('b.com'), robots: { ...scanNoDmarc('b.com').robots!, securityTxt: presentSecurityTxt } },
    'c.com': {
      ...scanNoDmarc('c.com'),
      dns: { ...scanNoDmarc('c.com').dns!, dmarc: { raw: 'v=DMARC1; p=reject', policy: 'reject', subdomainPolicy: null, rua: [], ruf: [], pct: 100 } },
    },
  };
  return ['a.com', 'b.com', 'c.com'].map((domain) => {
    const { failures, notes } = evaluateCheck(domain, scans[domain], {}, opts);
    return { domain, passed: failures.length === 0, failures, notes };
  });
}

test('fleet gate rollup: a check failing on 2/3 domains rolls up into one entry', () => {
  const fleet = fixtureFleetCheckResults();
  // Sanity: the per-domain fix-suggestion text really does differ (proves the
  // rollup groups by check name, not by exact failure text).
  const aDmarc = fleet.find((f) => f.domain === 'a.com')!.failures.find((f) => f.startsWith('DMARC'))!;
  const bDmarc = fleet.find((f) => f.domain === 'b.com')!.failures.find((f) => f.startsWith('DMARC'))!;
  assert.notEqual(aDmarc, bDmarc);

  const rollup = rollupCheckFailures(fleet);
  const dmarc = rollup.find((e) => e.name === 'DMARC missing');
  assert.ok(dmarc, 'DMARC missing should roll up across a.com and b.com');
  assert.equal(dmarc!.count, 2);
  assert.equal(dmarc!.totalDomains, 3);
  assert.deepEqual(dmarc!.domains.sort(), ['a.com', 'b.com']);
  assert.equal(formatRollupLine(dmarc!), 'same check fails on 2/3 domains: DMARC missing');

  // c.com's security.txt failure is unique — still present as its own
  // count-1 entry, matching "unique failures still print (per-domain)".
  const secTxt = rollup.find((e) => e.name === 'security.txt missing');
  assert.ok(secTxt);
  assert.equal(secTxt!.count, 1);
  assert.deepEqual(secTxt!.domains, ['c.com']);
});

test('fleet gate rollup: per-domain detail (the JSON/-v source data) is untouched by the rollup', () => {
  const fleet = fixtureFleetCheckResults();
  // The full failure text — including the per-domain fix suggestion the
  // rollup key strips — is still on each FleetCheckResult, which is exactly
  // what `peep fleet --format json` / `-v` prints per domain.
  const a = fleet.find((f) => f.domain === 'a.com')!;
  assert.ok(a.failures.some((f) => f.includes('a.com')), 'per-domain detail (e.g. the domain-specific DMARC fix) survives');
});

test('rollupCheckFailures: same check firing twice on one domain still counts that domain once', () => {
  const fleet: FleetCheckResult[] = [
    { domain: 'a.com', passed: false, notes: [], failures: ['DMARC missing — x', 'DMARC missing — y'] },
  ];
  const rollup = rollupCheckFailures(fleet);
  assert.equal(rollup.length, 1);
  assert.equal(rollup[0].count, 1);
});

test('rollupCheckFailures: route-scoped SEO failures group by route + check name', () => {
  const fleet: FleetCheckResult[] = [
    { domain: 'a.com', passed: false, notes: [], failures: ['SEO check "Title" not passing on /contact/ — "Contact" (7 chars — too short, aim for 30-60)'] },
    { domain: 'b.com', passed: false, notes: [], failures: ['SEO check "Title" not passing on /contact/ — "Reach Us" (8 chars — too short, aim for 30-60)'] },
  ];
  const rollup = rollupCheckFailures(fleet);
  assert.equal(rollup.length, 1);
  assert.equal(rollup[0].route, '/contact/');
  assert.equal(rollup[0].name, 'Title');
  assert.equal(rollup[0].count, 2);
  assert.equal(formatRollupLine(rollup[0]), '/contact/: Title on 2/2 domains');
});

test('classifyCheckFailure: known evaluateCheck() failure formats resolve to a stable check name', () => {
  assert.deepEqual(classifyCheckFailure('Route /de returned HTTP 404'), { route: '/de', name: 'Route unreachable' });
  assert.deepEqual(classifyCheckFailure('Route /de is NOINDEX — remove noindex before deploying'), { route: '/de', name: 'Route NOINDEX' });
  assert.deepEqual(classifyCheckFailure('HTTP 526 — origin not reachable'), { route: null, name: 'Site unreachable (HTTP error)' });
  assert.deepEqual(classifyCheckFailure('Security score 30/100 is below threshold 50 — fix security headers'), { route: null, name: 'Security score below threshold' });
  assert.deepEqual(classifyCheckFailure('Critical scanner error [dns]: timeout'), { route: null, name: 'Critical scanner error [dns]' });
});

test('classifyCheckFailure: unrecognized failure text still rolls up, falling back to the full text as the key', () => {
  const { route, name } = classifyCheckFailure('Some future check format not parsed yet');
  assert.equal(route, null);
  assert.equal(name, 'Some future check format not parsed yet');
});
