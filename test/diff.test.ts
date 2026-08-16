import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDiff, type DiffInput } from '../src/commands/diff.js';
import type { ScanResult, CorrelationFinding } from '../src/types.js';

function scan(domain: string, over: Partial<ScanResult> = {}): ScanResult {
  return {
    domain,
    url: `https://${domain}`,
    timestamp: '2026-01-01T00:00:00.000Z',
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
    ...over,
  };
}

function analytics(over: Partial<ScanResult['analytics'] & object> = {}) {
  return { ga4: [], gtm: [], adsense: [], umami: [], facebook: [], clarity: [], plausible: [], cloudflare: [], other: [], ...over };
}

function content(adultScore: number) {
  return { isAdult: adultScore >= 30, adultScore, signals: [], affiliateLinks: [], adNetworks: [], contentRating: null };
}

function input(scans: ScanResult[], findings?: CorrelationFinding[]): DiffInput {
  const di: DiffInput = { scans };
  if (findings) {
    di.correlation = { timestamp: 't', domains: scans.map((s) => s.domain), findings, score: 0, matrix: {}, summary: { critical: 0, high: 0, medium: 0, low: 0 } };
  }
  return di;
}

test('new and removed domains are reported', () => {
  const a = input([scan('a.com')]);
  const b = input([scan('a.com'), scan('b.com')]);
  const r = buildDiff(a, b, 'a', 'b');
  assert.ok(r.changes.some((c) => c.type === 'new_domain' && c.domain === 'b.com'));

  const r2 = buildDiff(b, a, 'b', 'a');
  assert.ok(r2.changes.some((c) => c.type === 'removed_domain' && c.domain === 'b.com'));
});

test('noindex transitions both directions', () => {
  const live = buildDiff(input([scan('a.com', { isNoindex: true })]), input([scan('a.com', { isNoindex: false })]), 'a', 'b');
  assert.ok(live.changes.some((c) => c.type === 'noindex_change' && /NOINDEX → LIVE/.test(c.detail)));

  const blocked = buildDiff(input([scan('a.com', { isNoindex: false })]), input([scan('a.com', { isNoindex: true })]), 'a', 'b');
  assert.ok(blocked.changes.some((c) => c.type === 'noindex_change' && /LIVE → NOINDEX/.test(c.detail)));
});

test('adult score change only fires at >= 10 point delta', () => {
  const small = buildDiff(input([scan('a.com', { content: content(20) })]), input([scan('a.com', { content: content(28) })]), 'a', 'b');
  assert.equal(small.changes.filter((c) => c.type === 'adult_score_change').length, 0, '8-point delta should not register');

  const big = buildDiff(input([scan('a.com', { content: content(20) })]), input([scan('a.com', { content: content(40) })]), 'a', 'b');
  assert.ok(big.changes.some((c) => c.type === 'adult_score_change' && /increased/.test(c.detail)));
});

test('analytics diff covers GA4, AdSense and GTM (added + removed)', () => {
  const before = input([scan('a.com', { analytics: analytics({ ga4: ['G-OLD'], gtm: ['GTM-KEEP'] }) })]);
  const after = input([scan('a.com', { analytics: analytics({ ga4: ['G-NEW'], gtm: ['GTM-KEEP'], adsense: ['ca-pub-1'] }) })]);
  const r = buildDiff(before, after, 'a', 'b');
  const details = r.changes.filter((c) => c.type === 'analytics_change').map((c) => c.detail);
  assert.ok(details.some((d) => /new GA4 ID: G-NEW/.test(d)));
  assert.ok(details.some((d) => /removed GA4 ID: G-OLD/.test(d)));
  assert.ok(details.some((d) => /new AdSense ID: ca-pub-1/.test(d)));
  // GTM-KEEP present in both → no GTM change
  assert.ok(!details.some((d) => /GTM/.test(d)), 'unchanged GTM ID should not appear');
});

test('new and resolved correlation findings are detected', () => {
  const f = (detail: string): CorrelationFinding => ({ type: 'shared-ga4', severity: 'critical', domains: ['a.com', 'b.com'], detail, evidence: 'e' });
  const before = input([scan('a.com')], [f('SHARED GA4 ID: G-1')]);
  const after = input([scan('a.com')], [f('SHARED GA4 ID: G-2')]);
  const r = buildDiff(before, after, 'a', 'b');
  assert.ok(r.changes.some((c) => c.type === 'new_finding' && /G-2/.test(c.detail)));
  assert.ok(r.changes.some((c) => c.type === 'resolved_finding' && /G-1/.test(c.detail)));
});

test('finding fingerprint is order-independent on domains', () => {
  const fa: CorrelationFinding = { type: 'shared-ip', severity: 'high', domains: ['a.com', 'b.com'], detail: 'x', evidence: 'e' };
  const fb: CorrelationFinding = { type: 'shared-ip', severity: 'high', domains: ['b.com', 'a.com'], detail: 'x', evidence: 'e' };
  const r = buildDiff(input([], [fa]), input([], [fb]), 'a', 'b');
  assert.equal(r.changes.filter((c) => c.type === 'new_finding' || c.type === 'resolved_finding').length, 0, 'same finding with reordered domains should be unchanged');
});

test('summary tallies added/removed/changed', () => {
  const a = input([scan('a.com', { isNoindex: true })]);
  const b = input([scan('a.com', { isNoindex: false }), scan('new.com')]);
  const r = buildDiff(a, b, 'a', 'b');
  assert.equal(r.summary.added, 1, 'one new domain');
  assert.equal(r.summary.changed, 1, 'one noindex change');
  assert.equal(r.summary.removed, 0);
});

test('identical inputs yield no changes', () => {
  const a = input([scan('a.com', { analytics: analytics({ ga4: ['G-SAME'] }) })]);
  const b = input([scan('a.com', { analytics: analytics({ ga4: ['G-SAME'] }) })]);
  const r = buildDiff(a, b, 'a', 'b');
  assert.equal(r.changes.length, 0);
});

test('security/SEO score drift and per-page audit regressions are reported; volatile fields are not', () => {
  const good = { name: 'Open Graph', present: true, value: '4/4', rating: 'good' as const, detail: 'ok' };
  const bad = { name: 'Open Graph', present: true, value: '3/4', rating: 'warning' as const, detail: 'Missing: og:image' };
  const page = (over: Partial<NonNullable<ScanResult['pageAudits']>[number]>) => ({
    route: '/de', url: 'https://a.com/de', statusCode: 200, ok: true, title: 't', htmlLang: 'de',
    canonicalUrl: 'https://a.com/de', isNoindex: false, hreflang: [], seoScore: 87, seoIssues: [], formEndpoints: [], ...over,
  });
  const before = scan('a.com', {
    timestamp: '2026-01-01T00:00:00.000Z', duration: 100,
    security: { score: 90, headers: [], formProviders: [] },
    seo: { score: 100, checks: [good], evaluated: 1, total: 12 },
    pageAudits: [page({})],
  });
  const after = scan('a.com', {
    timestamp: '2026-02-01T00:00:00.000Z', duration: 900,
    security: { score: 90, headers: [], formProviders: [] },
    seo: { score: 87, checks: [bad], evaluated: 1, total: 12 },
    pageAudits: [page({ seoScore: 79, seoIssues: [bad] })],
  });
  const r = buildDiff(input([before]), input([after]), 'a', 'b');
  const details = r.changes.map((ch) => ch.detail);
  assert.ok(details.some((d) => d.includes('SEO score 100 → 87 (regressed)')));
  assert.ok(details.some((d) => d.includes('a.com: SEO check now failing — Open Graph: Missing: og:image')));
  assert.ok(details.some((d) => d.includes('a.com/de: SEO check now failing — Open Graph')));
  assert.ok(details.some((d) => d.includes('/de SEO score 87 → 79')));
  assert.ok(!details.some((d) => /timestamp|duration|security score/.test(d)), 'unchanged/volatile fields must not appear');
  assert.equal(r.summary.changed, r.changes.length);
});

test('volatile-only drift diffs clean and footer counts', () => {
  const r = buildDiff(
    input([scan('a.com', { duration: 1, timestamp: '2026-01-01T00:00:00Z' })]),
    input([scan('a.com', { duration: 999, timestamp: '2027-01-01T00:00:00Z' })]),
    'a',
    'b',
  );
  assert.equal(r.changes.length, 0);
  assert.ok(r.compared);
  assert.ok(r.compared!.fields > 0);
  assert.ok(r.compared!.ignored.includes('duration'));
});
