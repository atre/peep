import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeCorrelation } from '../src/correlation/matrix.js';
import { buildReport, collapseCommodityPairwise } from '../src/correlation/scoring.js';
import type { ScanResult, HtmlResult, CorrelationFinding, AnalyticsResult } from '../src/types.js';

function makeScan(domain: string, overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    domain,
    url: `https://${domain}`,
    timestamp: new Date().toISOString(),
    duration: 100,
    isNoindex: false,
    dns: null,
    http: null,
    tls: null,
    whois: null,
    html: null,
    analytics: null,
    assets: null,
    robots: null,
    content: null,
    security: null,
    seo: null,
    tech: null,
    errors: [],
    ...overrides,
  };
}

function makeAnalytics(ga4: string[] = [], adsense: string[] = [], gtm: string[] = []) {
  return {
    ga4,
    gtm,
    adsense,
    umami: [],
    facebook: [],
    clarity: [],
    plausible: [],
    cloudflare: [],
    other: [],
  };
}

function makeDns(a: string[] = [], overrides: Record<string, any> = {}) {
  return {
    a,
    aaaa: [],
    mx: [],
    txt: [],
    ns: [],
    cname: [],
    googleVerification: null,
    microsoftVerification: null,
    facebookVerification: null,
    ...overrides,
  };
}

function makeSecurity(formProviders: string[] = []) {
  return { score: 0, headers: [], formProviders };
}

function makeAssets(overrides: Record<string, any> = {}) {
  return {
    faviconHash: null,
    faviconUrl: null,
    cssHashes: [],
    jsHashes: [],
    fontFamilies: [],
    fontSources: [],
    imageCount: 0,
    ogImages: [],
    ...overrides,
  };
}

function makeHtml(overrides: Partial<HtmlResult> = {}): HtmlResult {
  return {
    title: null,
    metaGenerator: null,
    metaViewport: null,
    metaRating: null,
    metaDescription: null,
    metaRobots: null,
    ogTags: {},
    twitterCards: {},
    canonicalUrl: null,
    scriptSources: [],
    stylesheetSources: [],
    htmlLang: null,
    headStructureHash: 'unique-head-' + Math.random(),
    bodyStructureHash: 'unique-body-' + Math.random(),
    inlineScriptHashes: [],
    inlineStyleHashes: [],
    comments: [],
    jsonLd: [],
    formEndpoints: [],
    emails: [],
    ...overrides,
  };
}

test('same GA4 ID → critical finding', () => {
  const scans = [
    makeScan('a.com', { analytics: makeAnalytics(['G-SHARED123']) }),
    makeScan('b.com', { analytics: makeAnalytics(['G-SHARED123']) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const ga4Finding = findings.find((f) => f.type === 'shared-ga4');
  assert.ok(ga4Finding, 'Expected shared-ga4 finding');
  assert.equal(ga4Finding!.severity, 'critical');
});

test('same cluster same IP → low finding (not high)', () => {
  const clusters = { 'clean-1': ['a.com', 'b.com'] };
  const scans = [
    makeScan('a.com', { dns: makeDns(['1.2.3.4']) }),
    makeScan('b.com', { dns: makeDns(['1.2.3.4']) }),
  ];
  const { findings } = computeCorrelation(scans, clusters);
  const ipFinding = findings.find((f) => f.domains.includes('a.com') && f.domains.includes('b.com') && f.type.includes('ip'));
  assert.ok(ipFinding, 'Expected IP finding');
  assert.equal(ipFinding!.severity, 'low', 'Same cluster IP sharing should be low severity');
});

test('different cluster same IP → high finding', () => {
  const clusters = { 'clean-1': ['a.com'], 'adult-1': ['b.com'] };
  const scans = [
    makeScan('a.com', { dns: makeDns(['1.2.3.4']) }),
    makeScan('b.com', { dns: makeDns(['1.2.3.4']) }),
  ];
  const { findings } = computeCorrelation(scans, clusters);
  const ipFinding = findings.find((f) =>
    f.domains.includes('a.com') && f.domains.includes('b.com') && f.type === 'shared-ip'
  );
  assert.ok(ipFinding, 'Expected cross-cluster shared-ip finding');
  assert.equal(ipFinding!.severity, 'high');
});

test('adult content on clean cluster → critical finding', () => {
  const clusters = { 'clean-1': ['a.com'] };
  const scans = [
    makeScan('a.com', {
      content: {
        isAdult: true,
        adultScore: 80,
        signals: [],
        affiliateLinks: [],
        adNetworks: [],
        contentRating: null,
      },
    }),
  ];
  const { findings } = computeCorrelation(scans, clusters);
  const adultFinding = findings.find((f) => f.type === 'cross-cluster-adult');
  assert.ok(adultFinding, 'Expected cross-cluster-adult finding');
  assert.equal(adultFinding!.severity, 'critical');
});

test('fleet-wide tracking ID on 3+ domains → critical finding', () => {
  const scans = [
    makeScan('a.com', { analytics: makeAnalytics(['G-FLEET123']) }),
    makeScan('b.com', { analytics: makeAnalytics(['G-FLEET123']) }),
    makeScan('c.com', { analytics: makeAnalytics(['G-FLEET123']) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const fleetFinding = findings.find((f) => f.type === 'fleet-wide-tracking-id');
  assert.ok(fleetFinding, 'Expected fleet-wide-tracking-id finding');
  assert.equal(fleetFinding!.severity, 'critical');
});

test('zero overlap → no cross-cluster findings', () => {
  const clusters = { 'clean-1': ['a.com'], 'clean-2': ['b.com'] };
  const scans = [
    makeScan('a.com', { analytics: makeAnalytics(['G-AAAAAAAA']) }),
    makeScan('b.com', { analytics: makeAnalytics(['G-BBBBBBBB']) }),
  ];
  const { findings } = computeCorrelation(scans, clusters);
  const critical = findings.filter((f) => f.severity === 'critical');
  assert.equal(critical.length, 0, 'No critical findings expected');
});

test('fixed-penalty isolation score: 1 critical → big drop', () => {
  const scans = [
    makeScan('a.com', { analytics: makeAnalytics(['G-SHARED']) }),
    makeScan('b.com', { analytics: makeAnalytics(['G-SHARED']) }),
  ];
  const { findings, matrix } = computeCorrelation(scans, {});
  const report = buildReport(scans, findings, matrix);
  // 1 pairwise critical = -25 (normalizer=1 for 2 domains), so score should be <= 75
  assert.ok(report.score <= 75, `Score should be <= 75 with 1 critical, got ${report.score}`);
  assert.ok(report.score > 0, 'Score should still be above 0');
});

test('fixed-penalty score: many domains with no issues = 100', () => {
  const scans = Array.from({ length: 30 }, (_, i) => makeScan(`site${i}.com`));
  const { findings, matrix } = computeCorrelation(scans, {});
  const report = buildReport(scans, findings, matrix);
  assert.equal(report.score, 100);
});

// ── Bug 2: WHOIS privacy placeholder should not trigger shared-registrant ──

function makeWhois(registrantOrg: string | null) {
  return {
    registrar: 'Some Registrar',
    createdDate: '2024-01-01',
    updatedDate: null,
    expiryDate: null,
    nameservers: [],
    registrantOrg,
    registrantCountry: null,
    dnssec: null,
    raw: '',
  };
}

test('WHOIS "DATA REDACTED" does not trigger shared-registrant', () => {
  const scans = [
    makeScan('a.com', { whois: makeWhois('DATA REDACTED') }),
    makeScan('b.com', { whois: makeWhois('DATA REDACTED') }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const reg = findings.find((f) => f.type === 'shared-registrant');
  assert.equal(reg, undefined, 'Should not fire shared-registrant for privacy placeholder');
});

test('WHOIS "REDACTED FOR PRIVACY" does not trigger shared-registrant', () => {
  const scans = [
    makeScan('a.com', { whois: makeWhois('REDACTED FOR PRIVACY') }),
    makeScan('b.com', { whois: makeWhois('REDACTED FOR PRIVACY') }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const reg = findings.find((f) => f.type === 'shared-registrant');
  assert.equal(reg, undefined, 'Should not fire shared-registrant for privacy placeholder');
});

test('WHOIS "Contact Privacy Inc." does not trigger shared-registrant', () => {
  const scans = [
    makeScan('a.com', { whois: makeWhois('Contact Privacy Inc. Customer 1234') }),
    makeScan('b.com', { whois: makeWhois('Contact Privacy Inc. Customer 1234') }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const reg = findings.find((f) => f.type === 'shared-registrant');
  assert.equal(reg, undefined, 'Should not fire shared-registrant for privacy service');
});

test('WHOIS real org name DOES trigger shared-registrant', () => {
  const scans = [
    makeScan('a.com', { whois: makeWhois('Acme Corp') }),
    makeScan('b.com', { whois: makeWhois('Acme Corp') }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const reg = findings.find((f) => f.type === 'shared-registrant');
  assert.ok(reg, 'Should fire shared-registrant for real org name');
});

// ── Bug 3: Pairwise dedup when fleet-wide finding exists ──

test('GA4 on 3+ sites: only fleet-wide finding, no pairwise dupes', () => {
  const scans = [
    makeScan('a.com', { analytics: makeAnalytics(['G-FLEET999']) }),
    makeScan('b.com', { analytics: makeAnalytics(['G-FLEET999']) }),
    makeScan('c.com', { analytics: makeAnalytics(['G-FLEET999']) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const fleet = findings.filter((f) => f.type === 'fleet-wide-tracking-id');
  const pairwise = findings.filter((f) => f.type === 'shared-ga4');
  assert.equal(fleet.length, 1, 'Should have exactly 1 fleet-wide finding');
  assert.equal(pairwise.length, 0, 'Should have no pairwise shared-ga4 findings (deduped)');
});

test('GA4 on exactly 2 sites: pairwise finding emitted (no fleet-wide)', () => {
  const scans = [
    makeScan('a.com', { analytics: makeAnalytics(['G-PAIR123']) }),
    makeScan('b.com', { analytics: makeAnalytics(['G-PAIR123']) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const fleet = findings.filter((f) => f.type === 'fleet-wide-tracking-id');
  const pairwise = findings.filter((f) => f.type === 'shared-ga4');
  assert.equal(fleet.length, 0, 'No fleet-wide finding for 2-site match');
  assert.equal(pairwise.length, 1, 'Should have pairwise shared-ga4 finding');
});

test('dedup: isolation score is higher when pairwise findings are suppressed', () => {
  const scans = [
    makeScan('a.com', { analytics: makeAnalytics(['G-DEDUP1']) }),
    makeScan('b.com', { analytics: makeAnalytics(['G-DEDUP1']) }),
    makeScan('c.com', { analytics: makeAnalytics(['G-DEDUP1']) }),
  ];
  const { findings, matrix } = computeCorrelation(scans, {});
  const report = buildReport(scans, findings, matrix);
  // With dedup: 1 fleet-wide critical (-25) = 75
  assert.equal(report.score, 75, 'Score should be 75 with only the fleet-wide finding');
});

// ── Bug 3: Isolation score normalization for large fleets ──

test('large fleet with infrastructure sharing does NOT score 0', () => {
  // 9 same-cluster domains all sharing MX — should NOT zero out
  const clusters = { 'main': ['s0.com','s1.com','s2.com','s3.com','s4.com','s5.com','s6.com','s7.com','s8.com'] };
  const scans = clusters.main.map((d) =>
    makeScan(d, {
      dns: makeDns([], { mx: [{ exchange: 'mail.shared.com', priority: 10 }] }),
      html: makeHtml({ headStructureHash: 'same-head', metaGenerator: 'WordPress 6.5' }),
    }),
  );
  const { findings, matrix } = computeCorrelation(scans, clusters);
  const report = buildReport(scans, findings, matrix);
  // With normalization + same-cluster downgrades, score should be well above 0
  assert.ok(report.score > 50, `9-domain same-cluster fleet should score > 50, got ${report.score}`);
});

test('fleet-wide critical still penalizes heavily even in large fleet', () => {
  // 9 domains sharing a GA4 ID → fleet-wide critical, not normalized
  const scans = Array.from({ length: 9 }, (_, i) =>
    makeScan(`s${i}.com`, { analytics: makeAnalytics(['G-FLEETWIDE']) }),
  );
  const { findings, matrix } = computeCorrelation(scans, {});
  const report = buildReport(scans, findings, matrix);
  // Fleet-wide critical = -25, should not be diluted
  assert.ok(report.score <= 75, `Fleet-wide critical should still penalize, got ${report.score}`);
});

// ── Feature #8: Same-cluster scoring downgrades ──

test('same-cluster shared MX → low severity', () => {
  const clusters = { 'main': ['a.com', 'b.com'] };
  const scans = [
    makeScan('a.com', { dns: makeDns([], { mx: [{ exchange: 'mail.example.com', priority: 10 }] }) }),
    makeScan('b.com', { dns: makeDns([], { mx: [{ exchange: 'mail.example.com', priority: 10 }] }) }),
  ];
  const { findings } = computeCorrelation(scans, clusters);
  const mx = findings.find((f) => f.type === 'shared-mx');
  assert.ok(mx, 'Expected shared-mx finding');
  assert.equal(mx!.severity, 'low', 'Same-cluster shared MX should be low');
});

test('cross-cluster shared MX → medium severity', () => {
  const clusters = { 'clean-1': ['a.com'], 'clean-2': ['b.com'] };
  const scans = [
    makeScan('a.com', { dns: makeDns([], { mx: [{ exchange: 'mail.example.com', priority: 10 }] }) }),
    makeScan('b.com', { dns: makeDns([], { mx: [{ exchange: 'mail.example.com', priority: 10 }] }) }),
  ];
  const { findings } = computeCorrelation(scans, clusters);
  const mx = findings.find((f) => f.type === 'shared-mx');
  assert.ok(mx, 'Expected shared-mx finding');
  assert.equal(mx!.severity, 'medium', 'Cross-cluster shared MX should be medium');
});

test('same-cluster shared head structure → suppressed, cross-cluster → medium', () => {
  const sameHtml = makeHtml({ headStructureHash: 'identical-head' });
  // Same cluster — finding suppressed (expected for template sites)
  const clusters1 = { 'main': ['a.com', 'b.com'] };
  const scans1 = [
    makeScan('a.com', { html: { ...sameHtml, bodyStructureHash: 'unique1' } }),
    makeScan('b.com', { html: { ...sameHtml, bodyStructureHash: 'unique2' } }),
  ];
  const r1 = computeCorrelation(scans1, clusters1);
  const head1 = r1.findings.find((f) => f.type === 'shared-head-structure');
  assert.equal(head1, undefined, 'Same-cluster shared head → no finding');

  // Cross cluster
  const clusters2 = { 'c1': ['a.com'], 'c2': ['b.com'] };
  const r2 = computeCorrelation(scans1, clusters2);
  const head2 = r2.findings.find((f) => f.type === 'shared-head-structure');
  assert.ok(head2);
  assert.equal(head2!.severity, 'medium', 'Cross-cluster shared head → medium');
});

// ── JSON-LD sameAs correlation ──

test('shared JSON-LD sameAs → high finding', () => {
  const scans = [
    makeScan('a.com', { html: makeHtml({ jsonLd: [{ type: 'Person', name: 'Alice', url: null, sameAs: ['https://twitter.com/alice'] }] }) }),
    makeScan('b.com', { html: makeHtml({ jsonLd: [{ type: 'Person', name: 'Alice', url: null, sameAs: ['https://twitter.com/alice'] }] }) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const jsonLdFinding = findings.find((f) => f.type === 'shared-jsonld-sameas');
  assert.ok(jsonLdFinding, 'Expected shared-jsonld-sameas finding');
  assert.equal(jsonLdFinding!.severity, 'high');
});

test('fleet-wide JSON-LD sameAs on 2+ sites → high finding', () => {
  const scans = [
    makeScan('a.com', { html: makeHtml({ jsonLd: [{ type: 'Person', name: 'A', url: null, sameAs: ['https://github.com/shared'] }] }) }),
    makeScan('b.com', { html: makeHtml({ jsonLd: [{ type: 'Person', name: 'B', url: null, sameAs: ['https://github.com/shared'] }] }) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const fleet = findings.find((f) => f.type === 'fleet-wide-jsonld-sameas');
  assert.ok(fleet, 'Expected fleet-wide-jsonld-sameas finding');
  assert.equal(fleet!.severity, 'high');
});

// ── Shared JS hash correlation ──

test('shared JS content hash → high finding (cross-cluster)', () => {
  const scans = [
    makeScan('a.com', { assets: { faviconHash: null, faviconUrl: null, cssHashes: [], jsHashes: [{ url: '/app.js', hash: 'abc123' }], fontFamilies: [], fontSources: [], imageCount: 0, ogImages: [] } }),
    makeScan('b.com', { assets: { faviconHash: null, faviconUrl: null, cssHashes: [], jsHashes: [{ url: '/main.js', hash: 'abc123' }], fontFamilies: [], fontSources: [], imageCount: 0, ogImages: [] } }),
  ];
  const clusters = { 'c1': ['a.com'], 'c2': ['b.com'] };
  const { findings } = computeCorrelation(scans, clusters);
  const jsFinding = findings.find((f) => f.type === 'shared-js-hash');
  assert.ok(jsFinding, 'Expected shared-js-hash finding');
  assert.equal(jsFinding!.severity, 'high');
});

test('CDN JS hash same-cluster → low (not medium)', () => {
  const makeAssets = (jsUrl: string) => ({ faviconHash: null, faviconUrl: null, cssHashes: [], jsHashes: [{ url: jsUrl, hash: 'cdn999' }], fontFamilies: [], fontSources: [], imageCount: 0, ogImages: [] });
  const scans = [
    makeScan('a.com', { assets: makeAssets('https://static.cloudflareinsights.com/beacon.min.js') }),
    makeScan('b.com', { assets: makeAssets('https://static.cloudflareinsights.com/beacon.min.js') }),
  ];
  const clusters = { 'main': ['a.com', 'b.com'] };
  const { findings } = computeCorrelation(scans, clusters);
  const cdnFinding = findings.find((f) => f.type === 'shared-js-hash-cdn');
  assert.ok(cdnFinding, 'Expected shared-js-hash-cdn finding');
  assert.equal(cdnFinding!.severity, 'low', 'Same-cluster CDN JS should be low');
});

test('CDN JS hash cross-cluster → medium', () => {
  const makeAssets = (jsUrl: string) => ({ faviconHash: null, faviconUrl: null, cssHashes: [], jsHashes: [{ url: jsUrl, hash: 'cdn999' }], fontFamilies: [], fontSources: [], imageCount: 0, ogImages: [] });
  const scans = [
    makeScan('a.com', { assets: makeAssets('https://cdn.jsdelivr.net/lib.js') }),
    makeScan('b.com', { assets: makeAssets('https://cdn.jsdelivr.net/lib.js') }),
  ];
  const clusters = { 'c1': ['a.com'], 'c2': ['b.com'] };
  const { findings } = computeCorrelation(scans, clusters);
  const cdnFinding = findings.find((f) => f.type === 'shared-js-hash-cdn');
  assert.ok(cdnFinding, 'Expected shared-js-hash-cdn finding');
  assert.equal(cdnFinding!.severity, 'medium', 'Cross-cluster CDN JS should be medium');
});

// ── Shared form endpoint correlation ──

test('shared Formspree endpoint → high finding', () => {
  const scans = [
    makeScan('a.com', { html: makeHtml({ formEndpoints: ['https://formspree.io/f/abc123'] }) }),
    makeScan('b.com', { html: makeHtml({ formEndpoints: ['https://formspree.io/f/abc123'] }) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const formFinding = findings.find((f) => f.type === 'shared-form-endpoint');
  assert.ok(formFinding, 'Expected shared-form-endpoint finding');
  assert.equal(formFinding!.severity, 'high');
});

// ── Shared twitter:site correlation ──

test('shared twitter:site handle → medium finding', () => {
  const scans = [
    makeScan('a.com', { html: makeHtml({ twitterCards: { 'twitter:site': '@alice' } }) }),
    makeScan('b.com', { html: makeHtml({ twitterCards: { 'twitter:site': '@alice' } }) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const twitterFinding = findings.find((f) => f.type === 'shared-twitter-site');
  assert.ok(twitterFinding, 'Expected shared-twitter-site finding');
  assert.equal(twitterFinding!.severity, 'medium');
});

test('same-cluster shared body structure → medium (downgraded from high)', () => {
  const sameHtml = makeHtml({ bodyStructureHash: 'identical-body' });
  const clusters = { 'main': ['a.com', 'b.com'] };
  const scans = [
    makeScan('a.com', { html: { ...sameHtml, headStructureHash: 'unique1' } }),
    makeScan('b.com', { html: { ...sameHtml, headStructureHash: 'unique2' } }),
  ];
  const { findings } = computeCorrelation(scans, clusters);
  const body = findings.find((f) => f.type === 'shared-body-structure');
  assert.ok(body);
  assert.equal(body!.severity, 'medium', 'Same-cluster shared body → medium');
});

// ── Fix 3: shared form/booking provider from CSP ──

test('shared CSP form provider → shared-form-provider medium finding', () => {
  const scans = [
    makeScan('a.com', { security: makeSecurity(['calendly.com']) }),
    makeScan('b.com', { security: makeSecurity(['calendly.com']) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const f = findings.find((x) => x.type === 'shared-form-provider');
  assert.ok(f, 'Expected shared-form-provider finding');
  assert.equal(f!.severity, 'medium');
  assert.ok(f!.detail.includes('calendly.com'));
});

test('fleet-wide CSP form provider on 2+ sites → fleet-wide-form-provider finding', () => {
  const scans = [
    makeScan('a.com', { security: makeSecurity(['formspree.io']) }),
    makeScan('b.com', { security: makeSecurity(['formspree.io']) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  const f = findings.find((x) => x.type === 'fleet-wide-form-provider');
  assert.ok(f, 'Expected fleet-wide-form-provider finding');
  assert.equal(f!.severity, 'medium');
});

test('no shared provider → no form-provider finding', () => {
  const scans = [
    makeScan('a.com', { security: makeSecurity(['calendly.com']) }),
    makeScan('b.com', { security: makeSecurity(['typeform.com']) }),
  ];
  const { findings } = computeCorrelation(scans, {});
  assert.equal(findings.find((x) => x.type === 'shared-form-provider'), undefined);
});

// ── Fix 4: commodity signals down-weighted vs genuine links ──

test('commodity infra overlap scores below a genuine favicon match in the matrix', () => {
  const commodityDns = () => makeDns([], {
    ns: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
    mx: [{ exchange: 'aspmx.l.google.com', priority: 1 }],
  });
  const fonts = makeAssets({ fontSources: ['https://cdn.example/inter-latin-400.woff2'] });
  const clusters = { c1: ['a.com'], c2: ['b.com'] };

  const commodity = [
    makeScan('a.com', { dns: commodityDns(), assets: fonts }),
    makeScan('b.com', { dns: commodityDns(), assets: fonts }),
  ];
  const { matrix: mCommodity } = computeCorrelation(commodity, clusters);

  const fav = makeAssets({ faviconHash: 'deadbeefcafe' });
  const genuine = [
    makeScan('a.com', { assets: fav }),
    makeScan('b.com', { assets: fav }),
  ];
  const { matrix: mGenuine } = computeCorrelation(genuine, clusters);

  const commScore = mCommodity['a.com']['b.com'];
  const genScore = mGenuine['a.com']['b.com'];
  assert.ok(commScore < genScore, `commodity (${commScore}) should score below genuine favicon (${genScore})`);
  assert.ok(commScore < 25, `commodity-only similarity should stay modest, got ${commScore}`);
});

test('commodity-only fleet stays better-isolated than a GA4-linked fleet', () => {
  const clusters = { c1: ['a.com'], c2: ['b.com'] };
  const commodity = [
    makeScan('a.com', { dns: makeDns([], { ns: ['ns1.cloudflare.com'], mx: [{ exchange: 'aspmx.l.google.com', priority: 1 }] }) }),
    makeScan('b.com', { dns: makeDns([], { ns: ['ns1.cloudflare.com'], mx: [{ exchange: 'aspmx.l.google.com', priority: 1 }] }) }),
  ];
  const rC = computeCorrelation(commodity, clusters);
  const reportC = buildReport(commodity, rC.findings, rC.matrix);

  const genuine = [
    makeScan('a.com', { analytics: makeAnalytics(['G-REALLINK']) }),
    makeScan('b.com', { analytics: makeAnalytics(['G-REALLINK']) }),
  ];
  const rG = computeCorrelation(genuine, {});
  const reportG = buildReport(genuine, rG.findings, rG.matrix);

  assert.ok(
    reportC.score > reportG.score,
    `commodity fleet (${reportC.score}) should out-isolate a GA4-linked fleet (${reportG.score})`,
  );
});

// ── Display-layer collapse of fleet-wide commodity pairwise spam ──

function pairFinding(type: string, a: string, b: string, detail: string): CorrelationFinding {
  return { type, severity: 'low', domains: [a, b], detail, evidence: 'x' };
}

test('collapseCommodityPairwise rolls fleet-wide commodity pairs into one line', () => {
  // 3 sites all sharing the same font file → C(3,2) = 3 identical pairwise lines.
  const detail = '1 shared font file(s): inter.woff2';
  const findings: CorrelationFinding[] = [
    pairFinding('shared-fonts', 'a.com', 'b.com', detail),
    pairFinding('shared-fonts', 'a.com', 'c.com', detail),
    pairFinding('shared-fonts', 'b.com', 'c.com', detail),
  ];
  const out = collapseCommodityPairwise(findings);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].domains, ['a.com', 'b.com', 'c.com']);
  assert.match(out[0].evidence, /collapsed from 3 pairs/);
});

test('collapseCommodityPairwise keeps small (1-2 pair) commodity groups intact', () => {
  const detail = 'Shared MX records: aspmx.l.google.com';
  const findings: CorrelationFinding[] = [
    pairFinding('shared-mx', 'a.com', 'b.com', detail),
    pairFinding('shared-mx', 'a.com', 'c.com', detail),
  ];
  assert.equal(collapseCommodityPairwise(findings).length, 2);
});

test('collapseCommodityPairwise drops pairwise covered by a fleet-wide rollup', () => {
  const detail = 'Shared form/booking provider(s) in CSP: calendly.com';
  const findings: CorrelationFinding[] = [
    pairFinding('shared-form-provider', 'a.com', 'b.com', detail),
    pairFinding('shared-form-provider', 'a.com', 'c.com', detail),
    pairFinding('shared-form-provider', 'b.com', 'c.com', detail),
    { type: 'fleet-wide-form-provider', severity: 'medium', domains: ['a.com', 'b.com', 'c.com'], detail: 'rollup', evidence: 'y' },
  ];
  const out = collapseCommodityPairwise(findings);
  // Only the rollup survives; all 3 pairwise lines are dropped.
  assert.deepEqual(out.map((f) => f.type), ['fleet-wide-form-provider']);
});

test('collapseCommodityPairwise leaves non-commodity findings untouched', () => {
  const findings: CorrelationFinding[] = [
    { type: 'shared-ga4', severity: 'critical', domains: ['a.com', 'b.com'], detail: 'GA4', evidence: 'z' },
  ];
  assert.deepEqual(collapseCommodityPairwise(findings), findings);
});

// ── 0.2: third-party IDs, email OPSEC, report collectors ──

function analyticsWith(over: Partial<AnalyticsResult> = {}): AnalyticsResult {
  return { ...makeAnalytics(), ...over };
}

test('shared Facebook pixel → critical pairwise finding (was never correlated)', () => {
  const results = [
    makeScan('a.com', { analytics: analyticsWith({ facebook: ['123456789012345'] }) }),
    makeScan('b.com', { analytics: analyticsWith({ facebook: ['123456789012345'] }) }),
  ];
  const { findings, matrix } = computeCorrelation(results);
  const f = findings.find((x) => x.type === 'shared-facebook-pixel');
  assert.ok(f, 'expected shared-facebook-pixel');
  assert.equal(f!.severity, 'critical');
  assert.ok(matrix['a.com']['b.com'] >= 40);
});

test('shared Clarity project → high; shared Plausible data-domain → critical', () => {
  const results = [
    makeScan('a.com', { analytics: analyticsWith({ clarity: ['abc123'], plausible: ['a.com'] }) }),
    makeScan('b.com', { analytics: analyticsWith({ clarity: ['abc123'], plausible: ['a.com'] }) }),
  ];
  const { findings } = computeCorrelation(results);
  assert.equal(findings.find((x) => x.type === 'shared-clarity')?.severity, 'high');
  assert.equal(findings.find((x) => x.type === 'shared-plausible-domain')?.severity, 'critical');
});

test('shared plausible.io hosted script URL is commodity, self-hosted script host is high', () => {
  const hosted = computeCorrelation([
    makeScan('a.com', { analytics: analyticsWith({ plausible: ['https://plausible.io/js/script.js'] }) }),
    makeScan('b.com', { analytics: analyticsWith({ plausible: ['https://plausible.io/js/script.js'] }) }),
  ]).findings;
  assert.ok(!hosted.some((f) => f.type.startsWith('shared-plausible')), 'hosted script must not link sites');
  const self = computeCorrelation([
    makeScan('a.com', { analytics: analyticsWith({ plausible: ['https://stats.ops.example/js/plausible.js'] }) }),
    makeScan('b.com', { analytics: analyticsWith({ plausible: ['https://stats.ops.example/js/plausible.js'] }) }),
  ]).findings;
  assert.equal(self.find((f) => f.type === 'shared-plausible-src')?.severity, 'high');
});

test('shared Stripe key → critical shared-third-party-id; shared Intercom app → high; Matomo idsite ignored', () => {
  const stripe = { name: 'Stripe Publishable Key', id: 'pk_live_abcdefghijklmnopqrstuvwxyz' };
  const intercom = { name: 'Intercom App', id: 'ab12cd34' };
  const matomo = { name: 'Matomo Site ID', id: '1' };
  const results = [
    makeScan('a.com', { analytics: analyticsWith({ other: [stripe, intercom, matomo] }) }),
    makeScan('b.com', { analytics: analyticsWith({ other: [stripe, intercom, matomo] }) }),
  ];
  const { findings } = computeCorrelation(results);
  const tp = findings.filter((f) => f.type === 'shared-third-party-id');
  assert.equal(tp.length, 2, `expected 2 third-party findings, got ${JSON.stringify(tp)}`);
  assert.equal(tp.find((f) => /Stripe/.test(f.detail))?.severity, 'critical');
  assert.equal(tp.find((f) => /Intercom/.test(f.detail))?.severity, 'high');
  assert.ok(!findings.some((f) => /Matomo/.test(f.detail)), 'Matomo idsite "1" collides across unrelated sites');
});

test('DNS:<vendor> entries in analytics.other are not double-counted as third-party IDs', () => {
  const dnsTok = { name: 'DNS:Stripe', id: 'abc' };
  const results = [
    makeScan('a.com', { analytics: analyticsWith({ other: [dnsTok] }) }),
    makeScan('b.com', { analytics: analyticsWith({ other: [dnsTok] }) }),
  ];
  assert.ok(!computeCorrelation(results).findings.some((f) => f.type === 'shared-third-party-id'));
});

test('third-party ID on 3+ sites → one fleet-wide finding naming the vendor, no pairwise dupes', () => {
  const key = { name: 'reCAPTCHA Site Key', id: '6LcAbCdEfGhIjKlMnOpQrStUvWxYz012345678_-' };
  const results = ['a.com', 'b.com', 'c.com'].map((d) => makeScan(d, { analytics: analyticsWith({ other: [key] }) }));
  const { findings } = computeCorrelation(results);
  const fleet = findings.filter((f) => f.type === 'fleet-wide-tracking-id');
  assert.equal(fleet.length, 1);
  assert.equal(fleet[0].severity, 'high');
  assert.match(fleet[0].detail, /reCAPTCHA Site Key 6Lc/);
  assert.equal(findings.filter((f) => f.type === 'shared-third-party-id').length, 0);
});

// ── Email OPSEC ──

function spf(raw: string) {
  const includes = [...raw.matchAll(/include:(\S+)/g)].map((m) => m[1]);
  const ip4 = [...raw.matchAll(/ip4:(\S+)/g)].map((m) => m[1]);
  return { raw, includes, ip4, ip6: [], redirect: null, all: '-all' as const };
}
function dmarc(rua: string[]) {
  return { raw: '', policy: 'reject', subdomainPolicy: null, rua, ruf: [], pct: null };
}

test('same DMARC rua mailbox on 2 sites → high fleet-wide shared-report-mailbox', () => {
  const results = [
    makeScan('a.com', { dns: makeDns([], { dmarc: dmarc(['dmarc-reports@ops.example']) }) }),
    makeScan('b.com', { dns: makeDns([], { dmarc: dmarc(['DMARC-Reports@ops.example']) }) }),
    makeScan('c.com', { dns: makeDns([], { dmarc: dmarc(['other@elsewhere.example']) }) }),
  ];
  const { findings } = computeCorrelation(results);
  const f = findings.find((x) => x.type === 'shared-report-mailbox');
  assert.ok(f, 'expected shared-report-mailbox');
  assert.equal(f!.severity, 'high');
  assert.deepEqual(f!.domains.sort(), ['a.com', 'b.com']);
});

test('same exposed contact email on 2 sites (not DMARC/CAA) → high shared-contact-email', () => {
  const results = [
    makeScan('a.com', { exposedIdentifiers: [{ kind: 'email', value: 'ops@agency.example', source: 'security.txt Contact' }] }),
    makeScan('b.com', { exposedIdentifiers: [{ kind: 'email', value: 'ops@agency.example', source: 'HTML mailto' }] }),
    makeScan('c.com', { exposedIdentifiers: [{ kind: 'email', value: 'other@elsewhere.example', source: 'HTML mailto' }] }),
  ];
  const { findings } = computeCorrelation(results);
  const f = findings.find((x) => x.type === 'shared-contact-email');
  assert.ok(f, 'expected shared-contact-email');
  assert.equal(f!.severity, 'high');
  assert.deepEqual(f!.domains.sort(), ['a.com', 'b.com']);
});

test('exposed email already covered by shared-report-mailbox is not double-reported', () => {
  const results = [
    makeScan('a.com', {
      dns: makeDns([], { dmarc: dmarc(['dmarc-reports@ops.example']) }),
      exposedIdentifiers: [{ kind: 'email', value: 'dmarc-reports@ops.example', source: 'DNS DMARC rua' }],
    }),
    makeScan('b.com', {
      dns: makeDns([], { dmarc: dmarc(['dmarc-reports@ops.example']) }),
      exposedIdentifiers: [{ kind: 'email', value: 'dmarc-reports@ops.example', source: 'DNS DMARC rua' }],
    }),
  ];
  const { findings } = computeCorrelation(results);
  assert.ok(!findings.some((x) => x.type === 'shared-contact-email'), 'DMARC-sourced address should only appear as shared-report-mailbox');
  assert.ok(findings.some((x) => x.type === 'shared-report-mailbox'));
});

test('DMARC reports delivered to a mailbox on another fleet domain → critical explicit link', () => {
  const results = [
    makeScan('a.com', { dns: makeDns([], { dmarc: dmarc(['dmarc@mail.b.com']) }) }),
    makeScan('b.com', { dns: makeDns() }),
  ];
  const { findings } = computeCorrelation(results);
  const f = findings.find((x) => x.type === 'report-address-on-fleet-domain');
  assert.ok(f);
  assert.equal(f!.severity, 'critical');
  assert.deepEqual(f!.domains, ['a.com', 'b.com']);
});

test('SPF include: of another fleet domain → critical; commodity include shared → no finding', () => {
  const results = [
    makeScan('a.com', { dns: makeDns([], { spf: spf('v=spf1 include:_spf.google.com include:b.com -all') }) }),
    makeScan('b.com', { dns: makeDns([], { spf: spf('v=spf1 include:_spf.google.com -all') }) }),
  ];
  const { findings } = computeCorrelation(results);
  assert.equal(findings.find((x) => x.type === 'spf-references-fleet-domain')?.severity, 'critical');
  assert.ok(!findings.some((x) => x.type === 'shared-spf-include'), 'google include is commodity');
});

test('shared custom SPF include → medium cross-cluster; shared SPF ip4 → high cross-cluster, low same-cluster', () => {
  const clusters = { one: ['a.com'], two: ['b.com'], same: ['c.com', 'd.com'] };
  const results = [
    makeScan('a.com', { dns: makeDns([], { spf: spf('v=spf1 include:spf.relay.example ip4:203.0.113.5 -all') }) }),
    makeScan('b.com', { dns: makeDns([], { spf: spf('v=spf1 include:spf.relay.example ip4:203.0.113.5 -all') }) }),
    makeScan('c.com', { dns: makeDns([], { spf: spf('v=spf1 ip4:198.51.100.9 -all') }) }),
    makeScan('d.com', { dns: makeDns([], { spf: spf('v=spf1 ip4:198.51.100.9 -all') }) }),
  ];
  const { findings } = computeCorrelation(results, clusters);
  const inc = findings.find((x) => x.type === 'shared-spf-include' && x.domains.includes('a.com'));
  assert.equal(inc?.severity, 'medium');
  const ipCross = findings.find((x) => x.type === 'shared-spf-ip' && x.domains.includes('a.com'));
  assert.equal(ipCross?.severity, 'high');
  const ipSame = findings.find((x) => x.type === 'shared-spf-ip' && x.domains.includes('c.com'));
  assert.equal(ipSame?.severity, 'low');
});

test('shared CAA accounturi → critical; shared CAA iodef mailbox → high', () => {
  const results = [
    makeScan('a.com', { dns: makeDns([], { caa: ['issue letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123', 'iodef mailto:certs@ops.example'] }) }),
    makeScan('b.com', { dns: makeDns([], { caa: ['issue letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123', 'iodef mailto:certs@ops.example'] }) }),
    makeScan('c.com', { dns: makeDns([], { caa: ['issue letsencrypt.org'] }) }),
  ];
  const { findings } = computeCorrelation(results);
  assert.equal(findings.find((x) => x.type === 'shared-caa-account')?.severity, 'critical');
  assert.equal(findings.find((x) => x.type === 'shared-report-mailbox')?.severity, 'high');
  assert.ok(!findings.some((x) => x.domains.includes('c.com') && /caa|mailbox/.test(x.type)), 'plain issue letsencrypt.org is commodity');
});

test('email findings are fleet-wide types: one critical costs 25 regardless of fleet size', () => {
  const results = [
    makeScan('a.com', { dns: makeDns([], { spf: spf('v=spf1 include:b.com -all') }) }),
    ...['b.com', 'c.com', 'd.com', 'e.com', 'f.com'].map((d) => makeScan(d, { dns: makeDns() })),
  ];
  const { findings, matrix } = computeCorrelation(results);
  const report = buildReport(results, findings, matrix);
  assert.equal(report.score, 75);
});

// ── Report collectors ──

test('same report-uri.com subdomain (different paths) → high shared-report-endpoint', () => {
  const results = [
    makeScan('a.com', { security: { ...makeSecurity(), reportEndpoints: ['acme.report-uri.com/r/d/csp/enforce'] } }),
    makeScan('b.com', { security: { ...makeSecurity(), reportEndpoints: ['acme.report-uri.com/a/d/g'] } }),
  ];
  const { findings } = computeCorrelation(results);
  const f = findings.find((x) => x.type === 'shared-report-endpoint');
  assert.equal(f?.severity, 'high');
  assert.match(f!.detail, /acme\.report-uri\.com/);
});

test('generic collector hosts only match on identical host/path', () => {
  const differ = computeCorrelation([
    makeScan('a.com', { security: { ...makeSecurity(), reportEndpoints: ['collector.example.net/a'] } }),
    makeScan('b.com', { security: { ...makeSecurity(), reportEndpoints: ['collector.example.net/b'] } }),
  ]).findings;
  assert.ok(!differ.some((x) => x.type === 'shared-report-endpoint'));
  const same = computeCorrelation([
    makeScan('a.com', { security: { ...makeSecurity(), reportEndpoints: ['collector.example.net/a'] } }),
    makeScan('b.com', { security: { ...makeSecurity(), reportEndpoints: ['collector.example.net/a'] } }),
  ]).findings;
  assert.ok(same.some((x) => x.type === 'shared-report-endpoint'));
});

test('mutual SPF includes (A→B, B→A) yield one critical finding, not two', () => {
  const results = [
    makeScan('a.com', { dns: makeDns([], { spf: spf('v=spf1 include:b.com -all') }) }),
    makeScan('b.com', { dns: makeDns([], { spf: spf('v=spf1 include:a.com -all') }) }),
  ];
  const { findings } = computeCorrelation(results);
  assert.equal(findings.filter((f) => f.type === 'spf-references-fleet-domain').length, 1);
});

test('CAA accounturi captured up to the next ; regardless of spacing', () => {
  const results = [
    makeScan('a.com', { dns: makeDns([], { caa: ['issue letsencrypt.org; accounturi=https://acme/acct/1; validationmethods=dns-01'] }) }),
    makeScan('b.com', { dns: makeDns([], { caa: ['issue letsencrypt.org;accounturi=https://acme/acct/1;validationmethods=dns-01'] }) }),
  ];
  assert.ok(computeCorrelation(results).findings.some((f) => f.type === 'shared-caa-account'));
});

test('shared mailbox on a fleet domain: explicit critical for the linked pair, third site still reported', () => {
  const results = [
    makeScan('a.com', { dns: makeDns([], { dmarc: dmarc(['dmarc@ops.b.com']) }) }),
    makeScan('b.com', { dns: makeDns() }),
    makeScan('c.com', { dns: makeDns([], { dmarc: dmarc(['dmarc@ops.b.com']) }) }),
  ];
  const { findings } = computeCorrelation(results);
  assert.equal(findings.filter((f) => f.type === 'report-address-on-fleet-domain').length, 2, 'a→b and c→b');
  const shared = findings.find((f) => f.type === 'shared-report-mailbox');
  assert.ok(shared, 'a.com and c.com share the mailbox — must still be reported');
  assert.deepEqual(shared!.domains.sort(), ['a.com', 'c.com']);
});
