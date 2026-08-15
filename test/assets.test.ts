import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cleanFontFamilies, splitTopLevelCommas } from '../src/scanners/assets.js';

// Assets scanner requires network (fetch), so test extraction logic offline

test('favicon URL extraction from HTML', () => {
  const html = '<link rel="icon" type="image/svg+xml" href="/favicon.svg">';
  const match = html.match(/<link[^>]+rel=['"](?:shortcut )?icon['"][^>]+href=['"]([^'"]+)['"]/i);
  assert.equal(match?.[1], '/favicon.svg');
});

test('favicon shortcut icon extraction', () => {
  const html = '<link rel="shortcut icon" href="/fav.ico">';
  const match = html.match(/<link[^>]+rel=['"](?:shortcut )?icon['"][^>]+href=['"]([^'"]+)['"]/i);
  assert.equal(match?.[1], '/fav.ico');
});

test('CSS URL extraction from link tags', () => {
  const html = `
    <link rel="stylesheet" href="/_astro/about.zvTAUSyp.css">
    <link rel="stylesheet" href="/styles/global.css">
    <link rel="icon" href="/favicon.ico">
  `;
  const cssRe = /<link[^>]+href=['"]([^'"]+\.css[^'"]*)['"]/gi;
  const urls: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = cssRe.exec(html)) !== null) {
    if (match[1]) urls.push(match[1]);
  }
  assert.equal(urls.length, 2);
  assert.ok(urls[0].includes('.css'));
});

test('JS URL extraction from script tags', () => {
  const html = `
    <script src="/_astro/Header.js"></script>
    <script src="https://cdn.example.com/lib.js"></script>
    <script>// inline</script>
  `;
  const jsRe = /<script[^>]+src=['"]([^'"]+\.js[^'"]*)['"]/gi;
  const urls: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = jsRe.exec(html)) !== null) {
    if (match[1]) urls.push(match[1]);
  }
  assert.equal(urls.length, 2);
});

test('SVG count in imageCount', () => {
  const html = `
    <svg viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>
    <div>
      <svg viewBox="0 0 200 200"><rect width="100" height="100"/></svg>
    </div>
    <img src="/photo.jpg">
  `;
  const imgTags = html.match(/<img\b/gi) ?? [];
  const svgTags = html.match(/<svg\b/gi) ?? [];
  const bgImages = html.match(/background(?:-image)?\s*:[^;]*url\(/gi) ?? [];
  const count = imgTags.length + svgTags.length + bgImages.length;
  assert.equal(count, 3); // 2 SVGs + 1 img
});

test('background-image counted', () => {
  const html = '<div style="background-image: url(/bg.jpg)"><div style="background-image: url(/hero.png)">';
  const bgImages = html.match(/background(?:-image)?\s*:[^;>"'{}]*url\(/gi) ?? [];
  assert.equal(bgImages.length, 2);
});

test('background shorthand with url counted', () => {
  const html = '<div style="background: url(/hero.png) center">';
  const bgImages = html.match(/background(?:-image)?\s*:[^;>"'{}]*url\(/gi) ?? [];
  assert.equal(bgImages.length, 1);
});

test('OG image extraction both attribute orders', () => {
  const html = `
    <meta property="og:image" content="https://example.com/og.png">
    <meta content="https://example.com/tw.png" property="og:image">
  `;
  const ogImageSet = new Set<string>();
  const re1 = /<meta[^>]+(?:property=['"]og:image['"]|name=['"]twitter:image['"])[^>]+content=['"]([^'"]+)['"]/gi;
  let m: RegExpExecArray | null;
  while ((m = re1.exec(html)) !== null) {
    if (m[1]) ogImageSet.add(m[1]);
  }
  const re2 = /<meta[^>]+content=['"]([^'"]+)['"]+[^>]+(?:property=['"]og:image['"]|name=['"]twitter:image['"])/gi;
  while ((m = re2.exec(html)) !== null) {
    if (m[1]) ogImageSet.add(m[1]);
  }
  assert.equal(ogImageSet.size, 2);
});

test('font-family extraction from CSS text', () => {
  const css = `
    @font-face { font-family: "Inter Variable"; src: url(/fonts/inter.woff2); }
    body { font-family: 'JetBrains Mono', monospace; }
    h1 { font-family: var(--font-sans); }
  `;
  const decls = css.match(/font-family\s*:\s*([^;}{]+)/gi) ?? [];
  const families = cleanFontFamilies(decls.map((m) => m.replace(/font-family\s*:\s*/i, '')));
  // Quotes stripped, no @font-face quirks, deduped real names. Generic families
  // (monospace) and var() references carry no fingerprint value and are dropped.
  assert.deepEqual(families, ['Inter Variable', 'JetBrains Mono']);
});

test('splitTopLevelCommas keeps var() and quoted commas intact', () => {
  assert.deepEqual(
    splitTopLevelCommas('var(--font-sans), var(--font-mono), "Helvetica, Neue"'),
    ['var(--font-sans)', ' var(--font-mono)', ' "Helvetica, Neue"'],
  );
});

test('cleanFontFamilies drops Tailwind v4 var() chains and system fallbacks', () => {
  // Real-world garbling: top-level var() refs, a nested var() with a doubled
  // comma, quoted emoji families, and stray empty tokens. None of it names a
  // real family — only "Archivo Black" should survive.
  const raw =
    'var(--font-sans), var(--font-mono), var(--default-font-family, ui-sans-serif, system-ui, sans-serif,, "Apple Color Emoji"), , Arial, "Archivo Black", -apple-system, BlinkMacSystemFont';
  const families = cleanFontFamilies([raw]);
  assert.deepEqual(families, ['Archivo Black']);
  // Nested var() must not spill its fallbacks as separate tokens either.
  assert.ok(!families.some((f) => f.includes('var(') || f === 'system-ui' || f === 'ui-sans-serif'));
});

test('cleanFontFamilies handles inline style values without truncating at quotes', () => {
  // Mimics what the scanner feeds in after extracting a style="" attribute body.
  const families = cleanFontFamilies(["'Playfair Display', 'Times New Roman', Georgia, serif"]);
  assert.deepEqual(families, ['Playfair Display']);
});

test('font source URL extraction from CSS', () => {
  const css = `
    @font-face {
      font-family: "Inter";
      src: url('/fonts/inter.woff2') format('woff2');
    }
    @font-face {
      font-family: "Mono";
      src: url(/fonts/mono.ttf);
    }
  `;
  const re = /url\(['"]?([^'")\s]+\.(?:woff2?|ttf|otf|eot)[^'")\s]*)/gi;
  const sources: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = re.exec(css)) !== null) {
    if (match[1]) sources.push(match[1]);
  }
  assert.equal(sources.length, 2);
  assert.ok(sources[0].endsWith('.woff2'));
  assert.ok(sources[1].endsWith('.ttf'));
});

test('resolveUrl handles various href formats', () => {
  // Replicate resolveUrl logic
  function resolveUrl(domain: string, href: string): string {
    let url: string;
    if (href.startsWith('http://') || href.startsWith('https://')) url = href;
    else if (href.startsWith('//')) url = `https:${href}`;
    else url = `https://${domain}${href.startsWith('/') ? '' : '/'}${href}`;
    if (!/^https?:\/\//i.test(url)) return `https://${domain}/invalid`;
    return url;
  }

  assert.equal(resolveUrl('example.com', '/favicon.ico'), 'https://example.com/favicon.ico');
  assert.equal(resolveUrl('example.com', 'https://cdn.test/file.js'), 'https://cdn.test/file.js');
  assert.equal(resolveUrl('example.com', '//cdn.test/file.js'), 'https://cdn.test/file.js');
  assert.equal(resolveUrl('example.com', 'style.css'), 'https://example.com/style.css');
});
