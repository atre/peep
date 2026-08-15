import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanTech } from '../src/scanners/tech.js';

test('Astro detected from /_astro/ path', () => {
  const result = scanTech('<script src="/_astro/app.js"></script>', {}, null, null);
  const astro = result.technologies.find((t) => t.name === 'Astro');
  assert.ok(astro);
  assert.equal(astro.confidence, 95);
});

test('Next.js detected from /_next/ path', () => {
  const result = scanTech('<script src="/_next/static/chunks/main.js"></script>', {}, null, null);
  const next = result.technologies.find((t) => t.name === 'Next.js');
  assert.ok(next);
});

test('WordPress detected from wp-content path', () => {
  const result = scanTech('<link rel="stylesheet" href="/wp-content/themes/mytheme/style.css">', {}, null, null);
  const wp = result.technologies.find((t) => t.name === 'WordPress');
  assert.ok(wp);
  assert.equal(wp.confidence, 95);
});

test('Cloudflare detected from server header', () => {
  const result = scanTech('', { server: 'cloudflare', 'cf-ray': 'abc123' }, null, null);
  const cf = result.technologies.find((t) => t.name === 'Cloudflare');
  assert.ok(cf);
  assert.equal(cf.confidence, 100);
});

test('Cloudflare Pages detected with CNAME to pages.dev', () => {
  const dnsResult = { a: [], aaaa: [], mx: [], txt: [], ns: [], cname: ['mysite.pages.dev'], googleVerification: null, microsoftVerification: null, facebookVerification: null };
  const result = scanTech('<script src="/_astro/app.js"></script>', { server: 'cloudflare', 'cf-ray': 'abc', 'cf-cache-status': 'HIT' }, null, dnsResult);
  const pages = result.technologies.find((t) => t.name === 'Cloudflare Pages');
  assert.ok(pages);
  assert.ok(pages.confidence >= 95);
});

test('Tailwind CSS detected from utility classes', () => {
  const html = `<div class="flex items-center gap-4 bg-blue-500 text-white px-4 py-2 mt-8 mb-4 rounded-lg shadow-lg hover:bg-blue-600 sm:px-6 md:flex-row lg:text-xl">
    <span class="text-sm text-gray-400 px-2 py-1 mt-2 mb-1 rounded bg-gray-100">test</span>
  </div>`;
  const result = scanTech(html, {}, null, null);
  const tw = result.technologies.find((t) => t.name === 'Tailwind CSS');
  assert.ok(tw, 'Tailwind CSS should be detected');
  assert.ok(tw.confidence >= 70);
});

test('Tailwind CSS not detected on plain HTML', () => {
  const html = '<div class="container"><p class="intro">Hello</p></div>';
  const result = scanTech(html, {}, null, null);
  const tw = result.technologies.find((t) => t.name === 'Tailwind CSS');
  assert.equal(tw, undefined, 'Tailwind should not be detected on non-utility HTML');
});

test('Nginx detected from server header', () => {
  const result = scanTech('', { server: 'nginx/1.21.4' }, null, null);
  const nginx = result.technologies.find((t) => t.name === 'Nginx');
  assert.ok(nginx);
  assert.equal(nginx.confidence, 100);
});

test('technologies sorted by confidence descending', () => {
  const result = scanTech(
    '<script src="/_astro/app.js"></script>',
    { server: 'cloudflare', 'cf-ray': 'abc' },
    null,
    null,
  );
  for (let i = 1; i < result.technologies.length; i++) {
    assert.ok(
      result.technologies[i].confidence <= result.technologies[i - 1].confidence,
      'Technologies should be sorted by confidence desc',
    );
  }
});

test('empty HTML and headers → no technologies', () => {
  const result = scanTech('', {}, null, null);
  assert.equal(result.technologies.length, 0);
});

test('GitHub Pages detected from CNAME to github.io', () => {
  const dnsResult = { a: [], aaaa: [], mx: [], txt: [], ns: [], cname: ['myuser.github.io'], googleVerification: null, microsoftVerification: null, facebookVerification: null };
  const result = scanTech('', {}, null, dnsResult);
  const gh = result.technologies.find((t) => t.name === 'GitHub Pages');
  assert.ok(gh);
  assert.equal(gh.confidence, 95);
});

test('cf-cache-status alone does not make a Cloudflare-proxied origin "Cloudflare Pages"', () => {
  // Hetzner + Docker behind the orange cloud: cf-ray, server: cloudflare and
  // cf-cache-status are all present, but nothing Pages-specific is.
  const result = scanTech('<div>app</div>', { server: 'cloudflare', 'cf-ray': 'abc', 'cf-cache-status': 'DYNAMIC' }, null, null);
  assert.equal(result.technologies.find((t) => t.name === 'Cloudflare Pages'), undefined);
  assert.ok(result.technologies.find((t) => t.name === 'Cloudflare'));
});
