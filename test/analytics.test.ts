import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanAnalytics } from '../src/scanners/analytics.js';

test('GA4 G-XXXXXXXX detected from gtag config', () => {
  const html = `<script>gtag('config', 'G-ABC123DEFG');</script>`;
  const r = scanAnalytics(html);
  assert.ok(r.ga4.includes('G-ABC123DEFG'), `Expected G-ABC123DEFG in ga4, got: ${r.ga4}`);
});

test('GTM-XXXXXX detected', () => {
  const html = `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABCD1234"></script>`;
  const r = scanAnalytics(html);
  assert.ok(r.gtm.some((id) => id.includes('ABCD1234')), `Expected GTM-ABCD1234 in gtm, got: ${r.gtm}`);
});

test('AdSense ca-pub-XXXXXXXXXX detected from data-ad-client', () => {
  const html = `<ins class="adsbygoogle" data-ad-client="ca-pub-1234567890"></ins>`;
  const r = scanAnalytics(html);
  assert.ok(r.adsense.includes('ca-pub-1234567890'), `Expected ca-pub-1234567890, got: ${r.adsense}`);
});

test('AdSense detected from google_ad_client', () => {
  const html = `<script>google_ad_client = "ca-pub-9876543210";</script>`;
  const r = scanAnalytics(html);
  assert.ok(r.adsense.includes('ca-pub-9876543210'), `Expected ca-pub-9876543210, got: ${r.adsense}`);
});

test('Umami websiteId UUID extraction', () => {
  const html = `<script defer src="/umami.js" data-website-id="12345678-1234-1234-1234-123456789abc"></script>`;
  const r = scanAnalytics(html);
  assert.equal(r.umami.length, 1);
  assert.equal(r.umami[0].websiteId, '12345678-1234-1234-1234-123456789abc');
});

test('Clean HTML returns all-empty analytics', () => {
  const html = `<!DOCTYPE html><html><head><title>Hello</title></head><body>World</body></html>`;
  const r = scanAnalytics(html);
  assert.equal(r.ga4.length, 0);
  assert.equal(r.gtm.length, 0);
  assert.equal(r.adsense.length, 0);
  assert.equal(r.umami.length, 0);
  assert.equal(r.cloudflare.length, 0);
});

test('Same GA4 ID not added twice (dedup)', () => {
  const html = `
    <script>gtag('config', 'G-TEST123456');</script>
    <script>'G-TEST123456'</script>
  `;
  const r = scanAnalytics(html);
  const count = r.ga4.filter((id) => id === 'G-TEST123456').length;
  assert.equal(count, 1, 'GA4 ID should only appear once');
});

test('Same AdSense ID not added twice (dedup)', () => {
  const html = `
    <ins data-ad-client="ca-pub-1234567890"></ins>
    <script>google_ad_client = "ca-pub-1234567890";</script>
  `;
  const r = scanAnalytics(html);
  const count = r.adsense.filter((id) => id === 'ca-pub-1234567890').length;
  assert.equal(count, 1, 'AdSense ID should only appear once');
});

// ── Bug 1: CF beacon URL should not appear in cloudflare[] ──

test('Cloudflare beacon.min.js URL is filtered out', () => {
  const html = `<script defer src="https://static.cloudflareinsights.com/beacon.min.js"></script>`;
  const r = scanAnalytics(html);
  assert.equal(r.cloudflare.length, 0, 'Beacon URL should not be in cloudflare[]');
});

test('Cloudflare 32-char hex token IS captured', () => {
  const html = `<script defer src='/cdn-cgi/scripts/abc.js' data-cf-beacon='{"token":"abcdef01234567890abcdef012345678"}'></script>`;
  const r = scanAnalytics(html);
  assert.equal(r.cloudflare.length, 1);
  assert.equal(r.cloudflare[0], 'abcdef01234567890abcdef012345678');
});

test('Cloudflare: page with both beacon URL and token only keeps token', () => {
  const html = `
    <script defer src="https://static.cloudflareinsights.com/beacon.min.js"
            data-cf-beacon='{"token":"aabbccdd11223344aabbccdd11223344"}'></script>
  `;
  const r = scanAnalytics(html);
  assert.equal(r.cloudflare.length, 1);
  assert.equal(r.cloudflare[0], 'aabbccdd11223344aabbccdd11223344');
});

// ── Bug 2: CF Web Analytics HTML-entity-encoded tokens ──

test('Cloudflare: HTML-entity-encoded &#34; token is captured', () => {
  const html = `<script defer src='/cdn-cgi/scripts/abc.js' data-cf-beacon='{&#34;token&#34;:&#34;aabbccdd11223344aabbccdd11223344&#34;}'></script>`;
  const r = scanAnalytics(html);
  assert.equal(r.cloudflare.length, 1);
  assert.equal(r.cloudflare[0], 'aabbccdd11223344aabbccdd11223344');
});

test('Cloudflare: entity-encoded without surrounding quotes also works', () => {
  const html = `<script data-cf-beacon={&#34;token&#34;:&#34;11223344aabbccdd11223344aabbccdd&#34;}></script>`;
  const r = scanAnalytics(html);
  assert.equal(r.cloudflare.length, 1);
  assert.equal(r.cloudflare[0], '11223344aabbccdd11223344aabbccdd');
});

// ── Bug 5: Umami multi-instance src pairing ──

test('Umami: single instance pairs websiteId with src', () => {
  const html = `<script defer src="https://analytics.example.com/umami.js" data-website-id="11111111-1111-1111-1111-111111111111"></script>`;
  const r = scanAnalytics(html);
  assert.equal(r.umami.length, 1);
  assert.equal(r.umami[0].websiteId, '11111111-1111-1111-1111-111111111111');
  assert.equal(r.umami[0].src, 'https://analytics.example.com/umami.js');
});

test('Umami: two instances each get their own src', () => {
  const html = `
    <script defer src="https://a.example.com/umami.js" data-website-id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"></script>
    <script defer src="https://b.example.com/umami.js" data-website-id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"></script>
  `;
  const r = scanAnalytics(html);
  assert.equal(r.umami.length, 2);
  const entryA = r.umami.find((u) => u.websiteId === 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
  const entryB = r.umami.find((u) => u.websiteId === 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
  assert.ok(entryA, 'Should have entry for first websiteId');
  assert.ok(entryB, 'Should have entry for second websiteId');
  assert.equal(entryA!.src, 'https://a.example.com/umami.js');
  assert.equal(entryB!.src, 'https://b.example.com/umami.js');
});
