import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { normalizeDomain, shortHash, md5, sha256, strippedPath, writeOutputFile, scoreColor, resolveScanningConfig, oneClickDnssecProvider, parsePagesFlag, isAdultCluster, collectExposedIdentifiers } from '../src/utils.js';
import type { ScanningConfig, ScanResult, DnsResult, RobotsResult } from '../src/types.js';

function dns(over: Partial<DnsResult> = {}): DnsResult {
  return { a: [], aaaa: [], mx: [], txt: [], ns: [], cname: [], googleVerification: null, microsoftVerification: null, facebookVerification: null, spf: null, dmarc: null, caa: [], ...over };
}

function robots(over: Partial<RobotsResult> = {}): RobotsResult {
  return {
    robotsTxt: null, robotsTxtHash: null, sitemapUrls: [], sitemapHash: null, affiliateRedirectPaths: [],
    adsTxt: null, adsTxtHash: null, adsTxtPubIds: [], securityTxt: null, humansTxt: null, ...over,
  } as never;
}

function scan(over: Partial<ScanResult> = {}): ScanResult {
  return {
    domain: 'example.com', url: 'https://example.com', timestamp: '', duration: 0, isNoindex: false,
    dns: null, http: null, tls: null, whois: null, html: null, analytics: null, assets: null,
    robots: null, content: null, security: null, seo: null, tech: null, errors: [],
    ...over,
  };
}

test('collectExposedIdentifiers: DMARC rua and security.txt Contact', () => {
  const r = collectExposedIdentifiers(scan({
    dns: dns({ dmarc: { raw: '', policy: 'none', subdomainPolicy: null, rua: ['a@b.com'], ruf: [], pct: null } }),
    robots: robots({ securityTxtSummary: { contacts: ['mailto:sec@b.com'], expires: null, expiresInDays: null, policy: null, hasSignature: false } }),
  }));
  assert.deepEqual(r, [
    { kind: 'email', value: 'a@b.com', source: 'DNS DMARC rua' },
    { kind: 'email', value: 'sec@b.com', source: 'security.txt Contact' },
  ]);
});

test('collectExposedIdentifiers: empty scan → empty array', () => {
  assert.deepEqual(collectExposedIdentifiers(scan()), []);
});

test('oneClickDnssecProvider identifies Cloudflare NS (trailing dot tolerant)', () => {
  assert.equal(oneClickDnssecProvider(['kara.ns.cloudflare.com', 'rob.ns.cloudflare.com']), 'Cloudflare');
  assert.equal(oneClickDnssecProvider(['kara.ns.cloudflare.com.']), 'Cloudflare');
});

test('oneClickDnssecProvider returns null for non-one-click providers', () => {
  assert.equal(oneClickDnssecProvider(['ns-1.awsdns-01.org']), null);
  assert.equal(oneClickDnssecProvider([]), null);
  // Must not match a domain that merely contains the string elsewhere.
  assert.equal(oneClickDnssecProvider(['ns.notcloudflare.com.evil.test']), null);
});

test('parsePagesFlag distinguishes a count from explicit routes', () => {
  assert.deepEqual(parsePagesFlag({ pages: '5' }), { pages: 5, pageRoutes: [] });
  assert.deepEqual(parsePagesFlag({ pages: '/de, /fr ,' }), { pages: 0, pageRoutes: ['/de', '/fr'] });
  assert.deepEqual(parsePagesFlag({}), { pages: 0, pageRoutes: [] });
});

const BASE_SCANNING: ScanningConfig = {
  concurrency: 5,
  timeout: 15000,
  userAgent: 'test',
  followRedirects: true,
  whoisEnabled: true,
  hashContent: true,
};

test('normalizeDomain strips https://', () => {
  assert.equal(normalizeDomain('https://example.com'), 'example.com');
});

test('normalizeDomain strips http://', () => {
  assert.equal(normalizeDomain('http://example.com'), 'example.com');
});

test('normalizeDomain strips trailing slash', () => {
  assert.equal(normalizeDomain('example.com/'), 'example.com');
});

test('normalizeDomain strips multiple trailing slashes', () => {
  assert.equal(normalizeDomain('https://example.com//'), 'example.com');
});

test('normalizeDomain lowercases', () => {
  assert.equal(normalizeDomain('EXAMPLE.COM'), 'example.com');
});

test('normalizeDomain leaves plain domain untouched', () => {
  assert.equal(normalizeDomain('example.com'), 'example.com');
});

test('normalizeDomain strips path', () => {
  assert.equal(normalizeDomain('https://example.com/some/path'), 'example.com');
});

test('normalizeDomain strips query string', () => {
  assert.equal(normalizeDomain('example.com?q=test'), 'example.com');
});

test('normalizeDomain strips hash fragment', () => {
  assert.equal(normalizeDomain('example.com#section'), 'example.com');
});

// ── Bug #3: detect silently-stripped paths ──

test('strippedPath returns the path segment', () => {
  assert.equal(strippedPath('example.com/de'), '/de');
});

test('strippedPath returns empty for a bare domain', () => {
  assert.equal(strippedPath('example.com'), '');
});

test('strippedPath ignores a lone trailing slash', () => {
  assert.equal(strippedPath('example.com/'), '');
});

test('strippedPath ignores multiple trailing slashes', () => {
  assert.equal(strippedPath('https://example.com//'), '');
});

test('strippedPath handles scheme + nested path', () => {
  assert.equal(strippedPath('https://example.com/de/page'), '/de/page');
});

test('strippedPath captures a query string', () => {
  assert.equal(strippedPath('example.com?q=1'), '?q=1');
});

test('strippedPath captures a fragment', () => {
  assert.equal(strippedPath('example.com#frag'), '#frag');
});

// ── Fix 2: --out shared writer ──

test('writeOutputFile writes content and returns an absolute path', () => {
  const target = join(tmpdir(), `peep-out-${process.pid}.json`);
  try {
    const full = writeOutputFile(target, '{"ok":true}');
    assert.ok(isAbsolute(full), 'returned path should be absolute');
    assert.equal(readFileSync(full, 'utf-8'), '{"ok":true}');
  } finally {
    rmSync(target, { force: true });
  }
});

// ── scoreColor ──

test('scoreColor: green at/above 80, yellow in [warn,80), red below warn', () => {
  assert.equal(scoreColor(80), 'green');
  assert.equal(scoreColor(100), 'green');
  assert.equal(scoreColor(79), 'yellow');
  assert.equal(scoreColor(50), 'yellow');
  assert.equal(scoreColor(49), 'red');
});

test('scoreColor: custom warn threshold', () => {
  assert.equal(scoreColor(70, 70), 'yellow');
  assert.equal(scoreColor(69, 70), 'red');
});

// ── resolveScanningConfig (fixes the --skip-content-hash no-op) ──

test('resolveScanningConfig: --skip-content-hash disables hashing even when default is true', () => {
  const r = resolveScanningConfig({ 'skip-content-hash': true }, BASE_SCANNING);
  assert.equal(r.hashContent, false);
});

test('resolveScanningConfig: --skip-content-hash wins over --hash-content', () => {
  const r = resolveScanningConfig({ 'skip-content-hash': true, 'hash-content': true }, BASE_SCANNING);
  assert.equal(r.hashContent, false);
});

test('resolveScanningConfig: --hash-content forces hashing when default is false', () => {
  const r = resolveScanningConfig({ 'hash-content': true }, { ...BASE_SCANNING, hashContent: false });
  assert.equal(r.hashContent, true);
});

test('resolveScanningConfig: no flags keeps the config default', () => {
  assert.equal(resolveScanningConfig({}, BASE_SCANNING).hashContent, true);
  assert.equal(resolveScanningConfig({}, { ...BASE_SCANNING, hashContent: false }).hashContent, false);
});

test('resolveScanningConfig: preserves other scanning fields', () => {
  const r = resolveScanningConfig({ 'skip-content-hash': true }, BASE_SCANNING);
  assert.equal(r.timeout, 15000);
  assert.equal(r.concurrency, 5);
  assert.equal(r.userAgent, 'test');
});

test('shortHash returns 12 hex chars', () => {
  const h = shortHash('hello');
  assert.equal(h.length, 12);
  assert.match(h, /^[0-9a-f]{12}$/);
});

test('shortHash is deterministic', () => {
  assert.equal(shortHash('test'), shortHash('test'));
});

test('shortHash different inputs give different hashes', () => {
  assert.notEqual(shortHash('abc'), shortHash('def'));
});

test('md5 returns 32 hex chars', () => {
  const h = md5('hello');
  assert.equal(h.length, 32);
  assert.match(h, /^[0-9a-f]{32}$/);
});

test('md5 known value', () => {
  // md5("") = d41d8cd98f00b204e9800998ecf8427e
  assert.equal(md5(''), 'd41d8cd98f00b204e9800998ecf8427e');
});

test('sha256 returns 64 hex chars', () => {
  const h = sha256('hello');
  assert.equal(h.length, 64);
  assert.match(h, /^[0-9a-f]{64}$/);
});

test('sha256 known value', () => {
  // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  assert.equal(sha256(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});


// ── isAdultCluster ──
// Regression: `cluster.startsWith('adult')` was case-sensitive at 7 call sites,
// so a cluster named "Adult" read as clean — failing the deploy gate for
// correctly-configured adult sites and raising spurious cross-cluster criticals.

test('isAdultCluster matches regardless of case', () => {
  for (const name of ['adult', 'Adult', 'ADULT', 'AdUlT']) {
    assert.equal(isAdultCluster(name), true, `expected ${name} to be an adult cluster`);
  }
});

test('isAdultCluster matches suffixed adult clusters', () => {
  assert.equal(isAdultCluster('adult-2'), true);
  assert.equal(isAdultCluster('Adult Cams'), true);
});

test('isAdultCluster tolerates surrounding whitespace', () => {
  assert.equal(isAdultCluster('  adult  '), true);
});

test('isAdultCluster is false for clean clusters and nullish input', () => {
  for (const name of ['clean', 'clean-1', 'Clean', 'grey', '']) {
    assert.equal(isAdultCluster(name), false, `expected ${name} to be clean`);
  }
  assert.equal(isAdultCluster(null), false);
  assert.equal(isAdultCluster(undefined), false);
});
