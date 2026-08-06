import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  validateScannerNames,
  expandScanners,
  KNOWN_SCANNERS,
  SELECTABLE_SCANNERS,
  parseSitemap,
  isHtmlPageUrl,
  extractSitemapLocs,
  resolvePageUrl,
  extractHreflang,
} from '../src/scanners/index.js';

// ── Bug #2: seo/security must be addressable via --only ──

test('validateScannerNames accepts real scanners', () => {
  assert.deepEqual(validateScannerNames(['dns', 'html', 'security']), []);
});

test('validateScannerNames accepts derived seo', () => {
  assert.deepEqual(validateScannerNames(['seo']), []);
});

test('security is a first-class scanner, not derived', () => {
  assert.ok(KNOWN_SCANNERS.includes('security'));
});

test('seo is selectable but not a real scanner', () => {
  assert.ok(SELECTABLE_SCANNERS.includes('seo'));
  assert.ok(!KNOWN_SCANNERS.includes('seo' as never));
});

test('validateScannerNames rejects genuinely unknown names', () => {
  assert.deepEqual(validateScannerNames(['bogus', 'html']), ['bogus']);
});

test('expandScanners expands seo to its source scanners', () => {
  assert.deepEqual([...expandScanners(['seo'])].sort(), ['html', 'http', 'robots', 'seo']);
});

test('expandScanners leaves plain scanners untouched', () => {
  assert.deepEqual(expandScanners(['dns', 'tls']), ['dns', 'tls']);
});

test('expandScanners dedupes when a source is also selected explicitly', () => {
  assert.deepEqual([...expandScanners(['seo', 'html'])].sort(), ['html', 'http', 'robots', 'seo']);
});

// ── Fix 1: --pages must follow <sitemapindex> into child sitemaps ──

const SITEMAP_INDEX_XML = `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-0.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-1.xml</loc></sitemap>
</sitemapindex>`;

const URLSET_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/contact/</loc></url>
  <url><loc>https://example.com/about/</loc></url>
  <url><loc>https://example.com/logo.png</loc></url>
  <url><loc>https://example.com/extra-sitemap.xml</loc></url>
</urlset>`;

test('parseSitemap detects a <sitemapindex> and exposes child sitemap locs', () => {
  const parsed = parseSitemap(SITEMAP_INDEX_XML, 'example.com');
  assert.equal(parsed.isIndex, true);
  assert.deepEqual(parsed.locs, [
    'https://example.com/sitemap-0.xml',
    'https://example.com/sitemap-1.xml',
  ]);
  // Index documents yield no page URLs directly — the orchestrator recurses
  assert.deepEqual(parsed.pageUrls, []);
});

test('parseSitemap on a urlset extracts HTML pages, skipping apex/assets/nested sitemaps', () => {
  const parsed = parseSitemap(URLSET_XML, 'example.com');
  assert.equal(parsed.isIndex, false);
  assert.deepEqual(parsed.pageUrls, [
    'https://example.com/contact/',
    'https://example.com/about/',
  ]);
});

test('isHtmlPageUrl rejects the apex, nested sitemaps, and binary assets', () => {
  assert.equal(isHtmlPageUrl('https://example.com/', 'example.com'), false);
  assert.equal(isHtmlPageUrl('https://example.com', 'example.com'), false);
  assert.equal(isHtmlPageUrl('https://example.com/sitemap-0.xml', 'example.com'), false);
  assert.equal(isHtmlPageUrl('https://example.com/logo.png', 'example.com'), false);
  assert.equal(isHtmlPageUrl('https://example.com/contact/', 'example.com'), true);
});

test('extractSitemapLocs tolerates whitespace around <loc> values', () => {
  const xml = '<urlset><url><loc>\n  https://example.com/x/  \n</loc></url></urlset>';
  assert.deepEqual(extractSitemapLocs(xml), ['https://example.com/x/']);
});

// ── Per-page audit helpers (explicit --pages routes) ──

test('resolvePageUrl resolves paths and passes through absolute URLs', () => {
  assert.equal(resolvePageUrl('example.com', '/de'), 'https://example.com/de');
  assert.equal(resolvePageUrl('example.com', 'de/contact'), 'https://example.com/de/contact');
  assert.equal(resolvePageUrl('example.com', 'https://cdn.example.com/fr'), 'https://cdn.example.com/fr');
});

test('extractHreflang pulls rel=alternate hreflang pairs in any attribute order', () => {
  const html = `
    <link rel="alternate" hreflang="de" href="https://example.com/de">
    <link href="https://example.com/fr" hreflang="fr" rel="alternate">
    <link rel="canonical" href="https://example.com/">
    <link rel="alternate" type="application/rss+xml" href="/feed.xml">
  `;
  const alts = extractHreflang(html);
  assert.deepEqual(alts, [
    { lang: 'de', href: 'https://example.com/de' },
    { lang: 'fr', href: 'https://example.com/fr' },
  ]);
});
