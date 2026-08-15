import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanAnalytics, mergeAnalytics } from '../src/scanners/analytics.js';

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

// ── Bounded-quantifier regressions ──
// The extractor patterns use bounded spans ({0,200}) instead of unbounded `.*?`
// so a hostile page can't drive quadratic matching. The bound must stay wide
// enough to still cross a tag's attributes — narrowing it to exclude quotes
// silently broke Plausible's data-domain detection once already.

test('Plausible data-domain is still extracted across attributes', () => {
  const html = `<script src="https://plausible.io/js/script.js" data-domain="mysite.com"></script>`;
  const r = scanAnalytics(html);
  assert.ok(r.plausible.includes('mysite.com'), `expected mysite.com, got ${JSON.stringify(r.plausible)}`);
});

test('Umami website id is still extracted across attributes', () => {
  const html = `<script src="https://umami.is/script.js" data-website-id="12345678-1234-1234-1234-123456789abc"></script>`;
  const r = scanAnalytics(html);
  assert.ok(r.umami.some((u) => u.websiteId === '12345678-1234-1234-1234-123456789abc'));
});

test('GTM id is still extracted from a googletagmanager URL', () => {
  const html = `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABCD123"></script>`;
  const r = scanAnalytics(html);
  assert.ok(r.gtm.some((id) => id.includes('ABCD123')));
});

test('extractors stay fast on adversarial repetition', () => {
  const blob = `<a href="exoclick.com zone juicyads.com spot hotjar.com plausible.io/js/ umami.is">`.repeat(20000);
  const start = Date.now();
  scanAnalytics(blob);
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 3000, `analytics scan took ${elapsed}ms on adversarial input — quantifier may be unbounded`);
});

// ── Third-party account IDs (0.2) ──

function other(html: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const o of scanAnalytics(html).other) (out[o.name] ??= []).push(o.id);
  return out;
}

test('Stripe publishable key extracted (live and test)', () => {
  const o = other(`<script>Stripe('pk_live_51Habcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP');</script>`);
  assert.deepEqual(o['Stripe Publishable Key'], ['pk_live_51Habcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP']);
});

test('Sentry DSN yields both the org id and the public key', () => {
  const o = other(`<script>Sentry.init({dsn:"https://0123456789abcdef0123456789abcdef@o4506123456.ingest.us.sentry.io/4506999999"})</script>`);
  assert.deepEqual(o['Sentry Org'], ['o4506123456']);
  assert.deepEqual(o['Sentry DSN'], ['0123456789abcdef0123456789abcdef']);
});

test('reCAPTCHA v2/v3 site key (6L…, 40 chars) extracted from data-sitekey and render=', () => {
  const key = '6LcAbCdEfGhIjKlMnOpQrStUvWxYz012345678_-';
  assert.equal(key.length, 40);
  const o = other(`<div class="g-recaptcha" data-sitekey="${key}"></div><script src="https://www.google.com/recaptcha/api.js?render=${key}"></script>`);
  assert.deepEqual(o['reCAPTCHA Site Key'], [key], 'deduped across two occurrences');
});

test('TikTok, LinkedIn, Pinterest, Reddit, X pixels', () => {
  const o = other(`
    <script>ttq.load('CABC123DEFGHIJKLMNOP');</script>
    <script>_linkedin_partner_id = "1234567";</script>
    <script>pintrk('load', '2612345678901');</script>
    <script>rdt('init','t2_abcd1234');</script>
    <script>twq('config','odc7x');</script>`);
  assert.deepEqual(o['TikTok Pixel'], ['CABC123DEFGHIJKLMNOP']);
  assert.deepEqual(o['LinkedIn Insight'], ['1234567']);
  assert.deepEqual(o['Pinterest Tag'], ['2612345678901']);
  assert.deepEqual(o['Reddit Pixel'], ['t2_abcd1234']);
  assert.deepEqual(o['X/Twitter Pixel'], ['odc7x']);
});

test('HubSpot portal, Intercom app, Crisp website, Tawk property, Mailchimp account, Shopify store', () => {
  const o = other(`
    <script src="//js-eu1.hs-scripts.com/1234567.js"></script>
    <script>window.intercomSettings = { api_base: "https://api-iam.intercom.io", app_id: "ab12cd34" };</script>
    <script>window.$crisp=[];window.CRISP_WEBSITE_ID="12345678-1234-1234-1234-123456789abc";</script>
    <script src="https://embed.tawk.to/5f1e2d3c4b5a69001234abcd/default"></script>
    <form action="https://example.us21.list-manage.com/subscribe/post?u=0123456789abcdef01234567&amp;id=abc123"></form>
    <img src="https://cdn.shopify.com/s/files/1/0123/4567/files/logo.png">`);
  assert.deepEqual(o['HubSpot Portal'], ['1234567']);
  assert.deepEqual(o['Intercom App'], ['ab12cd34']);
  assert.deepEqual(o['Crisp Website'], ['12345678-1234-1234-1234-123456789abc']);
  assert.deepEqual(o['Tawk.to Property'], ['5f1e2d3c4b5a69001234abcd']);
  assert.deepEqual(o['Mailchimp Account'], ['0123456789abcdef01234567']);
  assert.deepEqual(o['Shopify Store'], ['0123/4567']);
});

test('Google Ads conversion id, Bing UET tag, Yandex Metrika, PostHog, Segment', () => {
  const o = other(`
    <script>gtag('config', 'AW-1234567890');</script>
    <script>(function(w,d,t,r,u){var f,n,i;w[u]=w[u]||[],f=function(){var o={ti:"12345678", enableAutoSpaTracking: true};o.q=w[u],w[u]=new UET(o),w[u].push("pageLoad")}})(window,document,"script","//bat.bing.com/bat.js","uetq");</script>
    <script>ym(87654321, "init", {});</script>
    <script>posthog.init('phc_abcdefghijklmnopqrstuvwxyz0123456789ABCD', {api_host:'https://eu.posthog.com'})</script>
    <script>analytics.load("AbCdEfGhIjKlMnOpQrStUvWx");</script>`);
  assert.deepEqual(o['Google Ads Conversion'], ['1234567890']);
  assert.deepEqual(o['Bing UET Tag'], ['12345678']);
  assert.deepEqual(o['Yandex Metrika'], ['87654321']);
  assert.deepEqual(o['PostHog Key'], ['phc_abcdefghijklmnopqrstuvwxyz0123456789ABCD']);
  assert.deepEqual(o['Segment Write Key'], ['AbCdEfGhIjKlMnOpQrStUvWx']);
});

test('plain marketing page yields no third-party IDs (no false positives from prose)', () => {
  const html = `<!DOCTYPE html><html><body><p>Our stripe of products, ti: 123, AW-1 and 0x4000 hex, contact app_id later.</p>
    <script>var config = { ti: 12, projectId: "demo" };</script></body></html>`;
  assert.deepEqual(scanAnalytics(html).other, []);
});

test('DNS TXT verification tokens beyond Google/Facebook land in other as DNS:<vendor>', () => {
  const r = scanAnalytics('<html></html>', {
    a: [], aaaa: [], mx: [], ns: [], cname: [], googleVerification: null, microsoftVerification: null, facebookVerification: null,
    txt: ['stripe-verification=abc123def', 'apple-domain-verification=XyZ987', 'v=spf1 include:_spf.google.com ~all', 'openai-domain-verification=dv-abc'],
  });
  const names = r.other.map((o) => o.name).sort();
  assert.deepEqual(names, ['DNS:Apple Business', 'DNS:OpenAI', 'DNS:Stripe']);
});

test('GTM container seen via gtm.js?id= and inline GTM-XXXX is reported once', () => {
  const html = `<script src="https://www.googletagmanager.com/gtm.js?id=GTM-TH8KRSBJ"></script><noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-TH8KRSBJ"></iframe></noscript>`;
  assert.deepEqual(scanAnalytics(html).gtm, ['GTM-TH8KRSBJ']);
});

test('mergeAnalytics folds subpage IDs into the homepage result without duplicates or DNS tokens', () => {
  const home = scanAnalytics(`<script>gtag('config','G-HOMEHOME1')</script>`, {
    a: [], aaaa: [], mx: [], ns: [], cname: [], googleVerification: null, microsoftVerification: null, facebookVerification: null,
    txt: ['stripe-verification=abc'],
  });
  const checkout = scanAnalytics(`<script>gtag('config','G-HOMEHOME1'); Stripe('pk_live_51Habcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP');</script>`, {
    a: [], aaaa: [], mx: [], ns: [], cname: [], googleVerification: null, microsoftVerification: null, facebookVerification: null,
    txt: ['stripe-verification=abc'],
  });
  mergeAnalytics(home, checkout);
  assert.deepEqual(home.ga4, ['G-HOMEHOME1']);
  assert.deepEqual(home.other.map((o) => o.name), ['DNS:Stripe', 'Stripe Publishable Key']);
});
