import { test } from 'node:test';
import assert from 'node:assert/strict';
import { briefLines } from '../src/commands/scan.js';
import type { ScanResult, SeoCheck, SecurityHeader } from '../src/types.js';

function scan(over: Partial<ScanResult> = {}): ScanResult {
  return {
    domain: 'example.com', url: 'https://example.com', timestamp: '', duration: 0, isNoindex: false,
    dns: null, http: null, tls: null, whois: null, html: null, analytics: null, assets: null,
    robots: null, content: null, security: null, seo: null, tech: null, errors: [],
    ...over,
  };
}

function seoCheck(name: string, rating: SeoCheck['rating']): SeoCheck {
  return { name, present: rating === 'good', value: null, rating, detail: `${name} detail` };
}

function header(name: string, rating: SecurityHeader['rating']): SecurityHeader {
  return { name, present: rating === 'good', value: null, rating, detail: `${name} detail` };
}

test('header line: domain, SEO/SEC scores, NOINDEX/HTTP-error flags', () => {
  const lines = briefLines(scan({
    isNoindex: true,
    http: { statusCode: 503, headers: {}, serverHeader: null, poweredBy: null, contentType: null, timing: 1, redirectChain: [], setCookies: [], xRobotsTag: null, finalUrl: null, acceptLanguage: null },
    seo: { score: 67, checks: [], evaluated: 12, total: 12 },
    security: { score: 80, headers: [], formProviders: [] },
  }));
  assert.equal(lines[0], 'example.com  SEO 67  SEC 80  [NOINDEX]  [HTTP 503]');
});

test('only missing/bad checks appear — good and warning lines are dropped', () => {
  const lines = briefLines(scan({
    seo: { score: 40, checks: [seoCheck('Title', 'good'), seoCheck('Hreflang', 'warning'), seoCheck('Canonical URL', 'missing')], evaluated: 3, total: 12 },
    security: { score: 20, headers: [header('CSP', 'bad'), header('HSTS', 'good')], formProviders: [] },
  }));
  assert.ok(!lines.some((l) => l.includes('Title')), 'good SEO check must not appear');
  assert.ok(!lines.some((l) => l.includes('Hreflang')), 'warning SEO check must not appear');
  assert.ok(lines.some((l) => l.includes('Canonical URL')), 'missing SEO check must appear');
  assert.ok(!lines.some((l) => l.includes('HSTS')), 'good security header must not appear');
  assert.ok(lines.some((l) => l.includes('CSP')), 'bad security header must appear');
});

test('hard cap at 10 lines with a final "… +N more"', () => {
  const twelveMissing = Array.from({ length: 12 }, (_, i) => seoCheck(`Check${i}`, 'missing'));
  const tenMissing = Array.from({ length: 10 }, (_, i) => header(`Header${i}`, 'missing'));
  const lines = briefLines(scan({
    seo: { score: 40, checks: twelveMissing, evaluated: 12, total: 12 },
    security: { score: 20, headers: tenMissing, formProviders: [] },
  }));
  assert.ok(lines.length <= 10, `expected <= 10 lines, got ${lines.length}`);
  assert.ok(!lines.some((l) => /\+\s/.test(l)), 'no line should contain a "+"-rated (good) check');
  assert.match(lines[lines.length - 1], /more$/);
});

test('scan errors appear as detail lines', () => {
  const lines = briefLines(scan({ errors: [{ scanner: 'tls', error: 'connection refused' }] }));
  assert.ok(lines.some((l) => l.includes('tls') && l.includes('connection refused')));
});
