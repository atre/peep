import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateCheck, resolveExpectNoindex, type CheckGateOptions } from '../src/commands/check.js';
import type { ScanResult } from '../src/types.js';

function scan(over: Partial<ScanResult> = {}): ScanResult {
  return {
    domain: 'example.com',
    url: 'https://example.com',
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
    security: { score: 80, headers: [], formProviders: [] },
    seo: null,
    tech: null,
    errors: [],
    ...over,
  };
}

function opts(over: Partial<CheckGateOptions> = {}): CheckGateOptions {
  return {
    clusterOverride: null,
    securityThreshold: 50,
    requireSecurityTxt: false,
    expectNoindex: false,
    ...over,
  };
}

test('clean scan on a clean cluster, not noindex, good security → no failures', () => {
  const r = evaluateCheck('example.com', scan(), {}, opts());
  assert.deepEqual(r.failures, []);
  assert.deepEqual(r.notes, []);
});

// ── Bug #3: pre-launch noindex escape hatch ──

test('noindex without --expect/--prelaunch → fails, no note', () => {
  const r = evaluateCheck('example.com', scan({ isNoindex: true }), {}, opts());
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /NOINDEX/);
  assert.deepEqual(r.notes, []);
});

test('noindex with expectNoindex → converts to a note, never a failure', () => {
  const r = evaluateCheck('example.com', scan({ isNoindex: true }), {}, opts({ expectNoindex: true }));
  assert.deepEqual(r.failures, [], 'a declared pre-launch noindex must not fail the gate');
  assert.deepEqual(r.notes, ['noindex (declared pre-launch)']);
});

test('expectNoindex on a site that is NOT noindex → no-op, no phantom note', () => {
  const r = evaluateCheck('example.com', scan({ isNoindex: false }), {}, opts({ expectNoindex: true }));
  assert.deepEqual(r.failures, []);
  assert.deepEqual(r.notes, [], 'the escape hatch must not fabricate a note when there is nothing to excuse');
});

test('expectNoindex does not mask unrelated failures (e.g. low security score)', () => {
  const r = evaluateCheck(
    'example.com',
    scan({ isNoindex: true, security: { score: 10, headers: [], formProviders: [] } }),
    {},
    opts({ expectNoindex: true, securityThreshold: 50 }),
  );
  assert.deepEqual(r.notes, ['noindex (declared pre-launch)']);
  assert.equal(r.failures.length, 1, 'the noindex failure is excused, but a genuinely low security score still fails');
  assert.match(r.failures[0], /Security score/);
});

// ── Existing gate checks (unchanged by the pre-launch feature) ──

test('adult content on a clean cluster fails', () => {
  const r = evaluateCheck(
    'example.com',
    scan({ content: { isAdult: true, adultScore: 90, signals: [], affiliateLinks: [], adNetworks: [], contentRating: null } }),
    { clean: ['example.com'] },
    opts(),
  );
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /Adult content/);
});

test('adult content on an adult cluster does not fail', () => {
  const r = evaluateCheck(
    'example.com',
    scan({ content: { isAdult: true, adultScore: 90, signals: [], affiliateLinks: [], adNetworks: [], contentRating: null } }),
    { adult: ['example.com'] },
    opts(),
  );
  assert.deepEqual(r.failures, []);
});

test('security score below threshold fails', () => {
  const r = evaluateCheck('example.com', scan({ security: { score: 30, headers: [], formProviders: [] } }), {}, opts({ securityThreshold: 50 }));
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /Security score 30\/100/);
});

test('--require-security-txt fails when absent', () => {
  const r = evaluateCheck('example.com', scan({ robots: { robotsTxt: null, robotsTxtHash: null, sitemapUrls: [], sitemapHash: null, affiliateRedirectPaths: [], adsTxt: null, adsTxtHash: null, adsTxtPubIds: [], securityTxt: null, humansTxt: null } }), {}, opts({ requireSecurityTxt: true }));
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /security\.txt/);
});

test('critical scanner errors (dns/http/tls) fail the gate', () => {
  const r = evaluateCheck('example.com', scan({ errors: [{ scanner: 'http', error: 'getaddrinfo ENOTFOUND example.com' }] }), {}, opts());
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /Critical scanner error \[http\]/);
});

test('non-critical scanner errors (e.g. whois) do not fail the gate', () => {
  const r = evaluateCheck('example.com', scan({ errors: [{ scanner: 'whois', error: 'timeout' }] }), {}, opts());
  assert.deepEqual(r.failures, []);
});

test('--only without security skips the score gate and notes it instead of failing on 0/100', () => {
  const r = evaluateCheck('example.com', scan({ security: null }), {}, opts({ only: ['tls', 'robots'] }));
  assert.deepEqual(r.failures, []);
  assert.ok(r.notes.some((n) => n.includes('security score not evaluated')));
});

test('--only whois,tls,robots with --require-security-txt still checks robots (it ran)', () => {
  const r = evaluateCheck('example.com', scan({ security: null, robots: null }), {}, opts({ only: ['whois', 'tls', 'robots'], requireSecurityTxt: true }));
  assert.ok(r.failures.some((f) => f.includes('security.txt not found')));
});

test('without --only, a missing security result still fails the gate (0/100)', () => {
  const r = evaluateCheck('example.com', scan({ security: null }), {}, opts());
  assert.ok(r.failures.some((f) => f.includes('Security score 0/100')));
});

test('an error status fails the gate even when every other check passes', () => {
  const http = { statusCode: 526, headers: {}, serverHeader: 'cloudflare', poweredBy: null, timing: 10, redirectChain: [], setCookies: [], finalUrl: 'https://example.com/', xRobotsTag: null };
  const r = evaluateCheck('example.com', scan({ http: http as never }), {}, opts());
  assert.ok(r.failures.some((f) => f.startsWith('HTTP 526 — Cloudflare: origin TLS certificate invalid')));
});

const ogBad = { name: 'Open Graph', present: true, value: '3/4', rating: 'warning' as const, detail: 'Missing: og:image' };
const ogGood = { name: 'Open Graph', present: true, value: '4/4', rating: 'good' as const, detail: 'ok' };
function page(route: string, over: Record<string, unknown> = {}) {
  return { route, url: `https://example.com${route}`, statusCode: 200, ok: true, title: 't', htmlLang: 'de',
    canonicalUrl: null, isNoindex: false, hreflang: [], seoScore: 87, seoIssues: [], formEndpoints: [], ...over } as never;
}

test('--require-seo fails when a --pages route lost the named check; root passing is not enough', () => {
  const r = evaluateCheck('example.com', scan({
    seo: { score: 100, checks: [ogGood], evaluated: 1, total: 12 },
    pageAudits: [page('/de'), page('/de/products', { seoScore: 79, seoIssues: [ogBad] })],
  }), {}, opts({ requiredSeoChecks: ['open graph'] }));
  assert.equal(r.failures.length, 1);
  assert.match(r.failures[0], /"Open Graph" not passing on \/de\/products — Missing: og:image/);
});

test('--expect-hreflang exempts matching routes from the Hreflang gate', () => {
  const hreflangWarn = { name: 'Hreflang', present: false, value: null, rating: 'warning' as const, detail: 'No hreflang' };
  const audits = [page('/blog/a', { seoIssues: [hreflangWarn] })];
  const exempt = evaluateCheck('x.com', scan({ pageAudits: audits }), {}, opts({
    requiredSeoChecks: ['Hreflang'],
    expectHreflang: [{ glob: '/blog/*', value: 'none' }],
  }));
  assert.deepEqual(exempt.failures, []);

  const notExempt = evaluateCheck('x.com', scan({ pageAudits: audits }), {}, opts({ requiredSeoChecks: ['Hreflang'] }));
  assert.equal(notExempt.failures.length, 1);
});

test('--min-seo applies to root and every route, naming the failing checks', () => {
  const r = evaluateCheck('example.com', scan({
    seo: { score: 60, checks: [ogBad], evaluated: 1, total: 12 },
    pageAudits: [page('/de', { seoScore: 90 })],
  }), {}, opts({ minSeoScore: 80 }));
  assert.deepEqual(r.failures, ['SEO score 60/100 on / is below --min-seo 80 — failing: Open Graph']);
});

test('--pages routes must answer and must not be noindex (unless declared pre-launch)', () => {
  const audits = [page('/de'), page('/en', { ok: false, statusCode: 404 }), page('/fr', { isNoindex: true })];
  const r = evaluateCheck('example.com', scan({ pageAudits: audits }), {}, opts());
  assert.deepEqual(r.failures, ['Route /en returned HTTP 404', 'Route /fr is NOINDEX — remove noindex before deploying']);
  const pre = evaluateCheck('example.com', scan({ pageAudits: audits }), {}, opts({ expectNoindex: true }));
  assert.deepEqual(pre.failures, ['Route /en returned HTTP 404']);
  assert.ok(pre.notes.includes('/fr: noindex (declared pre-launch)'));
});

test('SEO gates are noted, not failed, when html was excluded by --only', () => {
  const r = evaluateCheck('example.com', scan({ security: null }), {}, opts({ only: ['tls'], minSeoScore: 90 }));
  assert.deepEqual(r.failures, []);
  assert.ok(r.notes.some((n) => n.startsWith('SEO gates not evaluated')));
});

// ── resolveExpectNoindex: --stage pre-launch alias ──

test('resolveExpectNoindex: --stage pre-launch behaves like --expect noindex', () => {
  assert.equal(resolveExpectNoindex({ stage: 'pre-launch' }), true);
});

test('resolveExpectNoindex: existing aliases still work, and false by default', () => {
  assert.equal(resolveExpectNoindex({ prelaunch: true }), true);
  assert.equal(resolveExpectNoindex({ 'allow-noindex': true }), true);
  assert.equal(resolveExpectNoindex({ expect: 'noindex' }), true);
  assert.equal(resolveExpectNoindex({}), false);
});

test('resolveExpectNoindex: unknown --stage value throws, not a silent no-op', () => {
  assert.throws(() => resolveExpectNoindex({ stage: 'staging' }), /unknown --stage value/);
});
