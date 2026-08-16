import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSeo } from '../src/scanners/seo.js';
import type { HtmlResult, RobotsResult } from '../src/types.js';

function html(over: Partial<HtmlResult> = {}): HtmlResult {
  return {
    title: 'A reasonably sized page title for testing SEO scoring logic',
    metaGenerator: null,
    metaViewport: 'width=device-width, initial-scale=1',
    metaRating: null,
    metaDescription: 'x'.repeat(140),
    metaRobots: null,
    ogTags: { 'og:title': 't', 'og:description': 'd', 'og:image': 'i', 'og:type': 'website' },
    twitterCards: { 'twitter:card': 'summary', 'twitter:title': 't' },
    canonicalUrl: 'https://example.com/',
    scriptSources: [],
    stylesheetSources: [],
    htmlLang: 'en',
    headStructureHash: 'h',
    bodyStructureHash: 'b',
    inlineScriptHashes: [],
    inlineStyleHashes: [],
    comments: [],
    jsonLd: [{ type: 'WebSite', name: 'x', url: 'https://example.com', sameAs: [] }],
    formEndpoints: [],
    emails: [],
    ...over,
  };
}

function robots(over: Partial<RobotsResult> = {}): RobotsResult {
  return {
    robotsTxt: 'User-agent: *',
    robotsTxtHash: 'abc',
    sitemapUrls: ['https://example.com/sitemap.xml'],
    sitemapHash: 'def',
    affiliateRedirectPaths: [],
    adsTxt: null,
    adsTxtHash: null,
    adsTxtPubIds: [],
    securityTxt: null,
    humansTxt: null,
    ...over,
  };
}

test('full inputs with everything present → score 100', () => {
  const r = scanSeo({ html: html(), robots: robots(), hasHreflang: true, statusCode: 200 });
  assert.equal(r.score, 100);
});

// ── Bug #1: unscanned sources must be "not evaluated", never failing ──

test('robots not scanned → robots.txt and Sitemap checks omitted entirely', () => {
  const r = scanSeo({
    html: html(), robots: null, hasHreflang: true, statusCode: 200,
    htmlScanned: true, robotsScanned: false,
  });
  const names = r.checks.map((c) => c.name);
  assert.ok(!names.includes('robots.txt'), 'robots.txt must not be evaluated when robots scanner did not run');
  assert.ok(!names.includes('Sitemap'), 'Sitemap must not be evaluated when robots scanner did not run');
});

test('robots not scanned → no false penalty (--only html still scores 100)', () => {
  const full = scanSeo({ html: html(), robots: robots(), hasHreflang: true, statusCode: 200 });
  const htmlOnly = scanSeo({
    html: html(), robots: null, hasHreflang: true, statusCode: 200,
    htmlScanned: true, robotsScanned: false,
  });
  assert.equal(full.score, 100);
  assert.equal(htmlOnly.score, 100, 'omitting an unscanned source must not lower the score');
});

test('robots scanned but genuinely absent → counted as missing and lowers score', () => {
  const r = scanSeo({
    html: html(),
    robots: robots({ robotsTxt: null, robotsTxtHash: null, sitemapUrls: [] }),
    hasHreflang: true, statusCode: 200,
  });
  const robotsCheck = r.checks.find((c) => c.name === 'robots.txt');
  assert.ok(robotsCheck, 'robots.txt should be evaluated when robots scanner ran');
  assert.equal(robotsCheck!.rating, 'missing');
  assert.ok(r.score !== null && r.score < 100, 'genuine absence (scanner ran, nothing found) must lower the score');
});

// ── Bug #3: a fetch failure must not read as an evaluated-and-failing page ──

test('fetch failed (neither html nor robots produced a result) → score is null, not 0 or 100', () => {
  const r = scanSeo({ html: null, robots: null, htmlScanned: false, robotsScanned: false });
  assert.equal(r.score, null, 'a derived score with nothing to derive from must be "not evaluated", never a number');
  assert.deepEqual(r.checks, [], 'no checks should be fabricated when nothing was fetched');
});

test('fetch failed but --only selected html → still not evaluated, no false "No <title> tag"', () => {
  // Mirrors scanners/index.ts: html was selected via --only, but the HTTP fetch
  // it depends on errored, so result.html stayed null. htmlScanned must reflect
  // that (false) — NOT "was html selected" (which would still be true here).
  const r = scanSeo({ html: null, robots: null, htmlScanned: false, robotsScanned: false, statusCode: undefined });
  const titleCheck = r.checks.find((c) => c.name === 'Title');
  assert.equal(titleCheck, undefined, 'Title must not be evaluated — and must never claim "No <title> tag" — when the fetch failed');
  assert.equal(r.score, null);
});

test('fetch failed for html but robots scanner succeeded independently → robots-derived checks still evaluated, html checks are not', () => {
  const r = scanSeo({ html: null, robots: robots(), htmlScanned: false, robotsScanned: true, statusCode: undefined });
  const names = r.checks.map((c) => c.name);
  assert.ok(names.includes('robots.txt'), 'robots.txt ran independently of the failed page fetch, so it should still be evaluated');
  assert.ok(!names.includes('Title'), 'Title depends on the failed fetch and must not be evaluated');
  assert.ok(r.score !== null, 'partial evaluation (robots ran) yields a real score, not "not evaluated"');
});

test('html not scanned → only robots-derived checks evaluated', () => {
  const r = scanSeo({ html: null, robots: robots(), htmlScanned: false, robotsScanned: true });
  const names = r.checks.map((c) => c.name);
  assert.ok(names.includes('robots.txt'));
  assert.ok(names.includes('Sitemap'));
  assert.ok(!names.includes('Title'), 'Title must not be evaluated when html scanner did not run');
  assert.ok(!names.includes('Hreflang'), 'Hreflang is html-derived and must not be evaluated');
  assert.equal(r.score, 100);
});

test('no status code observed → HTTPS check omitted (not a silent penalty)', () => {
  const r = scanSeo({ html: html(), robots: robots(), hasHreflang: true });
  const httpsCheck = r.checks.find((c) => c.name === 'HTTPS');
  assert.equal(httpsCheck, undefined, 'HTTPS must not be evaluated without a status code');
  assert.equal(r.score, 100, 'missing status code must not penalize the score');
});

test('defaults: scanned flags omitted → both sources evaluated', () => {
  const r = scanSeo({ html: html({ title: null }), robots: robots() });
  const title = r.checks.find((c) => c.name === 'Title');
  assert.ok(title, 'Title evaluated by default');
  assert.equal(title!.rating, 'missing');
  const robotsCheck = r.checks.find((c) => c.name === 'robots.txt');
  assert.ok(robotsCheck, 'robots.txt evaluated by default');
});

test('no twitter:* tags at all → "missing", not "partially configured"', () => {
  const html = { title: 'A perfectly sized page title for testing', metaDescription: null, metaRobots: null, metaViewport: null,
    metaGenerator: null, htmlLang: 'en', canonicalUrl: null, ogTags: {}, twitterCards: {}, headStructureHash: 'x',
    bodyStructureHash: 'x', scriptSources: [], stylesheetSources: [], inlineScriptHashes: [], comments: [], jsonLd: [], formEndpoints: [] } as never;
  const r = scanSeo({ html, robots: null, robotsScanned: false });
  const tw = r.checks.find((ch) => ch.name === 'Twitter Card')!;
  assert.equal(tw.rating, 'missing');
});

// ── noindex pages: Canonical URL / Hreflang / Structured Data don't apply ──

test('noindex page: canonical/hreflang/JSON-LD not evaluated', () => {
  const r = scanSeo({ html: html({ canonicalUrl: null, jsonLd: [] }), robots: robots(), statusCode: 200, noindex: true });
  assert.equal(r.checks.find((c) => c.name === 'Canonical URL'), undefined);
  assert.equal(r.checks.find((c) => c.name === 'Hreflang'), undefined);
  assert.equal(r.checks.find((c) => c.name === 'Structured Data'), undefined);
  assert.deepEqual(r.skipped, ['Canonical URL', 'Hreflang', 'Structured Data']);
  assert.equal(r.score, 100);
});

// ── i18n site: an untranslated page's missing hreflang is not a bug ──

test('site is i18n (siteHreflang set) but this page has no hreflang → distinct wording, still warning', () => {
  const r = scanSeo({ html: html(), robots: robots(), hasHreflang: false, siteHreflang: ['en', 'de', 'x-default'], statusCode: 200 });
  const check = r.checks.find((c) => c.name === 'Hreflang')!;
  assert.equal(check.rating, 'warning');
  assert.match(check.detail, /site is i18n \(root: en, de, x-default\) — this page has none/);
});

test('site is not i18n (no siteHreflang) → generic hreflang wording', () => {
  const r = scanSeo({ html: html(), robots: robots(), hasHreflang: false, statusCode: 200 });
  const check = r.checks.find((c) => c.name === 'Hreflang')!;
  assert.equal(check.detail, 'No hreflang — add if site has multiple language versions');
});

// ── ±5 threshold tolerance: borderline title/description length stays "good" ──

test('borderline title/description length stays good', () => {
  const r = scanSeo({ html: html({ title: 'x'.repeat(63), metaDescription: 'x'.repeat(161) }), robots: robots(), statusCode: 200 });
  const title = r.checks.find((c) => c.name === 'Title')!;
  const desc = r.checks.find((c) => c.name === 'Meta Description')!;
  assert.equal(title.rating, 'good');
  assert.match(title.detail, /borderline/);
  assert.equal(desc.rating, 'good');
  assert.match(desc.detail, /borderline/);

  const tooLong = scanSeo({ html: html({ title: 'x'.repeat(66) }), robots: robots(), statusCode: 200 });
  assert.equal(tooLong.checks.find((c) => c.name === 'Title')!.rating, 'warning');
});
