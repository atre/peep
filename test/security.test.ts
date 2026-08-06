import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanSecurity, extractCspFormProviders } from '../src/scanners/security.js';

const GOOD_HEADERS: Record<string, string> = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'geolocation=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-resource-policy': 'same-origin',
};

const EMPTY_HEADERS: Record<string, string> = {};

test('all good headers → high score', () => {
  const r = scanSecurity(GOOD_HEADERS, { hasSecurityTxt: true });
  assert.ok(r.score >= 80, `Expected score >= 80, got ${r.score}`);
});

test('all missing headers → low score', () => {
  const r = scanSecurity(EMPTY_HEADERS);
  assert.ok(r.score < 50, `Expected score < 50, got ${r.score}`);
});

test('each header appears in results', () => {
  const r = scanSecurity(GOOD_HEADERS);
  const headerNames = r.headers.map((h) => h.name);
  assert.ok(headerNames.includes('Strict-Transport-Security'));
  assert.ok(headerNames.includes('Content-Security-Policy'));
  assert.ok(headerNames.includes('X-Frame-Options'));
});

test('X-Powered-By present → warning rating', () => {
  const headers = { 'x-powered-by': 'PHP/8.1' };
  const r = scanSecurity(headers);
  const xpb = r.headers.find((h) => h.name === 'X-Powered-By');
  assert.ok(xpb, 'X-Powered-By header check should exist');
  assert.equal(xpb!.rating, 'warning');
});

test('X-Powered-By absent → good rating', () => {
  const r = scanSecurity(GOOD_HEADERS);
  const xpb = r.headers.find((h) => h.name === 'X-Powered-By');
  assert.ok(xpb);
  assert.equal(xpb!.rating, 'good');
});

test('HSTS with includeSubDomains → good rating', () => {
  const r = scanSecurity(GOOD_HEADERS);
  const hsts = r.headers.find((h) => h.name === 'Strict-Transport-Security');
  assert.ok(hsts);
  assert.equal(hsts!.rating, 'good');
});

test('missing CSP → missing rating', () => {
  const r = scanSecurity(EMPTY_HEADERS);
  const csp = r.headers.find((h) => h.name === 'Content-Security-Policy');
  assert.ok(csp);
  assert.equal(csp!.rating, 'missing');
});

test('score is between 0 and 100', () => {
  const r1 = scanSecurity(GOOD_HEADERS);
  const r2 = scanSecurity(EMPTY_HEADERS);
  assert.ok(r1.score >= 0 && r1.score <= 100);
  assert.ok(r2.score >= 0 && r2.score <= 100);
});

// ── Bug #1: CSP directive-level parsing ──

test('CSP: style-src unsafe-inline with clean script-src → good rating', () => {
  const headers = {
    'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
  };
  const r = scanSecurity(headers);
  const csp = r.headers.find((h) => h.name === 'Content-Security-Policy');
  assert.ok(csp);
  assert.equal(csp!.rating, 'good', 'style-src unsafe-inline should not penalize');
  assert.ok(csp!.detail.includes('style-src unsafe-inline'), 'Should note style-src unsafe-inline');
});

test('CSP: script-src unsafe-inline → warning (regardless of style-src)', () => {
  const headers = {
    'content-security-policy': "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
  };
  const r = scanSecurity(headers);
  const csp = r.headers.find((h) => h.name === 'Content-Security-Policy');
  assert.ok(csp);
  assert.equal(csp!.rating, 'warning');
  assert.ok(csp!.detail.includes('script-src'), 'Should mention script-src specifically');
});

test('CSP: default-src unsafe-eval → warning', () => {
  const headers = {
    'content-security-policy': "default-src 'self' 'unsafe-eval'",
  };
  const r = scanSecurity(headers);
  const csp = r.headers.find((h) => h.name === 'Content-Security-Policy');
  assert.ok(csp);
  assert.equal(csp!.rating, 'warning');
});

// ── Feature #4: security.txt bonus ──

test('security.txt present → good rating in results', () => {
  const r = scanSecurity(EMPTY_HEADERS, { hasSecurityTxt: true });
  const secTxt = r.headers.find((h) => h.name === 'security.txt');
  assert.ok(secTxt);
  assert.equal(secTxt!.rating, 'good');
});

test('security.txt absent → missing rating', () => {
  const r = scanSecurity(EMPTY_HEADERS, { hasSecurityTxt: false });
  const secTxt = r.headers.find((h) => h.name === 'security.txt');
  assert.ok(secTxt);
  assert.equal(secTxt!.rating, 'missing');
});

test('security.txt not checked when robots scanner excluded → no entry', () => {
  const r = scanSecurity(EMPTY_HEADERS);
  const secTxt = r.headers.find((h) => h.name === 'security.txt');
  assert.equal(secTxt, undefined, 'security.txt should not appear when hasSecurityTxt is undefined');
});

test('security.txt boosts score', () => {
  const without = scanSecurity(GOOD_HEADERS, { hasSecurityTxt: false });
  const withTxt = scanSecurity(GOOD_HEADERS, { hasSecurityTxt: true });
  assert.ok(withTxt.score > without.score, `With security.txt (${withTxt.score}) should score higher than without (${without.score})`);
});

// ── Feature #6: COOP/COEP/CORP ──

test('COOP: same-origin → good', () => {
  const r = scanSecurity({ 'cross-origin-opener-policy': 'same-origin' });
  const coop = r.headers.find((h) => h.name === 'Cross-Origin-Opener-Policy');
  assert.ok(coop);
  assert.equal(coop!.rating, 'good');
});

test('COEP: require-corp → good', () => {
  const r = scanSecurity({ 'cross-origin-embedder-policy': 'require-corp' });
  const coep = r.headers.find((h) => h.name === 'Cross-Origin-Embedder-Policy');
  assert.ok(coep);
  assert.equal(coep!.rating, 'good');
});

test('CORP: same-origin → good', () => {
  const r = scanSecurity({ 'cross-origin-resource-policy': 'same-origin' });
  const corp = r.headers.find((h) => h.name === 'Cross-Origin-Resource-Policy');
  assert.ok(corp);
  assert.equal(corp!.rating, 'good');
});

test('CORP: cross-origin → good (public resource sharing)', () => {
  const r = scanSecurity({ 'cross-origin-resource-policy': 'cross-origin' });
  const corp = r.headers.find((h) => h.name === 'Cross-Origin-Resource-Policy');
  assert.ok(corp);
  assert.equal(corp!.rating, 'good');
});

// ── HTML comments OPSEC warning ──

test('HTML comments present → warning in results', () => {
  const r = scanSecurity(EMPTY_HEADERS, { commentCount: 5 });
  const comments = r.headers.find((h) => h.name === 'HTML comments');
  assert.ok(comments);
  assert.equal(comments!.rating, 'warning');
  assert.ok(comments!.detail.includes('5'));
});

test('zero HTML comments → no entry', () => {
  const r = scanSecurity(EMPTY_HEADERS, { commentCount: 0 });
  const comments = r.headers.find((h) => h.name === 'HTML comments');
  assert.equal(comments, undefined);
});

test('HTML comments do not affect score', () => {
  const without = scanSecurity(GOOD_HEADERS);
  const withComments = scanSecurity(GOOD_HEADERS, { commentCount: 10 });
  assert.equal(without.score, withComments.score);
});

// ── CSP script allowlist cross-reference ──

test('script from unlisted origin → CSP allowlist warning', () => {
  const headers = { 'content-security-policy': "script-src 'self'" };
  const r = scanSecurity(headers, {
    scriptSources: ['https://cdn.external.com/analytics.js'],
    domain: 'example.com',
  });
  const cspCheck = r.headers.find((h) => h.name === 'CSP script allowlist');
  assert.ok(cspCheck, 'CSP script allowlist entry should exist');
  assert.equal(cspCheck!.rating, 'warning');
  assert.ok(cspCheck!.detail.includes('cdn.external.com'));
});

test('script from self origin → no CSP allowlist warning', () => {
  const headers = { 'content-security-policy': "script-src 'self'" };
  const r = scanSecurity(headers, {
    scriptSources: ['/app.js', 'https://example.com/main.js'],
    domain: 'example.com',
  });
  const cspCheck = r.headers.find((h) => h.name === 'CSP script allowlist');
  assert.equal(cspCheck, undefined, 'No warning when all scripts match self');
});

test('script matching CSP wildcard → no warning', () => {
  const headers = { 'content-security-policy': "script-src 'self' *.cloudflare.com" };
  const r = scanSecurity(headers, {
    scriptSources: ['https://static.cloudflare.com/beacon.js'],
    domain: 'example.com',
  });
  const cspCheck = r.headers.find((h) => h.name === 'CSP script allowlist');
  assert.equal(cspCheck, undefined);
});

test('CSP with https: allows all → no warning', () => {
  const headers = { 'content-security-policy': "script-src https:" };
  const r = scanSecurity(headers, {
    scriptSources: ['https://any.cdn.com/lib.js'],
    domain: 'example.com',
  });
  const cspCheck = r.headers.find((h) => h.name === 'CSP script allowlist');
  assert.equal(cspCheck, undefined);
});

test('CSP allowlist does not affect score', () => {
  const headers = { 'content-security-policy': "script-src 'self'" };
  const without = scanSecurity(headers);
  const withScripts = scanSecurity(headers, {
    scriptSources: ['https://cdn.external.com/x.js'],
    domain: 'example.com',
  });
  assert.equal(without.score, withScripts.score);
});

// ── CORS wildcard check ──

test('access-control-allow-origin: * → warning', () => {
  const r = scanSecurity({ 'access-control-allow-origin': '*' });
  const cors = r.headers.find((h) => h.name === 'Access-Control-Allow-Origin');
  assert.ok(cors, 'CORS entry should exist');
  assert.equal(cors!.rating, 'warning');
});

test('no CORS header → no CORS entry', () => {
  const r = scanSecurity(EMPTY_HEADERS);
  const cors = r.headers.find((h) => h.name === 'Access-Control-Allow-Origin');
  assert.equal(cors, undefined);
});

test('CORS does not affect score', () => {
  const without = scanSecurity(GOOD_HEADERS);
  const withCors = scanSecurity({ ...GOOD_HEADERS, 'access-control-allow-origin': '*' });
  assert.equal(without.score, withCors.score);
});

// ── Fix 3: form/booking provider extraction from CSP ──

test('extractCspFormProviders picks Calendly + Formspree across directives', () => {
  const headers = {
    'content-security-policy': "default-src 'self'; frame-src https://calendly.com; connect-src https://formspree.io",
  };
  assert.deepEqual(extractCspFormProviders(headers), ['calendly.com', 'formspree.io']);
});

test('extractCspFormProviders canonicalizes wildcard subdomains', () => {
  const headers = { 'content-security-policy': 'frame-src *.calendly.com' };
  assert.deepEqual(extractCspFormProviders(headers), ['calendly.com']);
});

test('extractCspFormProviders accepts bare host tokens (no scheme)', () => {
  const headers = { 'content-security-policy': 'frame-src calendly.com' };
  assert.deepEqual(extractCspFormProviders(headers), ['calendly.com']);
});

test('extractCspFormProviders ignores non-provider hosts and keyword tokens', () => {
  const headers = { 'content-security-policy': "default-src 'self' https://cdn.example.com 'unsafe-inline'" };
  assert.deepEqual(extractCspFormProviders(headers), []);
});

test('extractCspFormProviders returns [] when there is no CSP', () => {
  assert.deepEqual(extractCspFormProviders({}), []);
});

test('scanSecurity surfaces formProviders on the result', () => {
  const r = scanSecurity({ 'content-security-policy': 'frame-src calendly.com; connect-src formspree.io' });
  assert.deepEqual(r.formProviders, ['calendly.com', 'formspree.io']);
});

test('scanSecurity formProviders is [] without CSP', () => {
  assert.deepEqual(scanSecurity(EMPTY_HEADERS).formProviders, []);
});
