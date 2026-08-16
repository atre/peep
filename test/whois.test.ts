import { test } from 'node:test';
import assert from 'node:assert/strict';
import { whoisStatusLine } from '../src/commands/scan.js';
import { withExpiresIn } from '../src/scanners/whois.js';
import type { ScanResult, WhoisResult } from '../src/types.js';

function whois(over: Partial<WhoisResult> = {}): WhoisResult {
  return { registrar: null, createdDate: null, updatedDate: null, expiryDate: null, nameservers: [], registrantOrg: null, registrantCountry: null, dnssec: null, raw: '', ...over };
}

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
    security: null,
    seo: null,
    tech: null,
    errors: [],
    ...over,
  };
}

test('whois scanner failed and was explicitly selected → status line with reason', () => {
  const line = whoisStatusLine(
    scan({ whois: null, errors: [{ scanner: 'whois', error: 'unavailable: whois binary not found; RDAP 404' }] }),
    ['whois'],
  );
  assert.equal(line, 'WHOIS: unavailable (unavailable: whois binary not found; RDAP 404)');
});

test('whois not selected via --only → no status line', () => {
  const line = whoisStatusLine(scan({ whois: null }), ['dns']);
  assert.equal(line, null);
});

test('whois populated with real data → no status line', () => {
  const line = whoisStatusLine(scan({
    whois: { registrar: 'Example Registrar', createdDate: '2020-01-01', updatedDate: null, expiryDate: null, nameservers: [], registrantOrg: null, registrantCountry: null, dnssec: null, raw: '' },
  }));
  assert.equal(line, null);
});

// ── withExpiresIn ──

test('withExpiresIn: no expiryDate → expiresIn null', () => {
  assert.equal(withExpiresIn(whois()).expiresIn, null);
});

test('withExpiresIn: unparseable expiryDate → expiresIn null', () => {
  assert.equal(withExpiresIn(whois({ expiryDate: 'not-a-date' })).expiresIn, null);
});

test('withExpiresIn: future date → positive day count', () => {
  const future = new Date(Date.now() + 10 * 86_400_000).toISOString();
  const r = withExpiresIn(whois({ expiryDate: future }));
  assert.ok(r.expiresIn != null && r.expiresIn >= 9 && r.expiresIn <= 10, `expected ~10, got ${r.expiresIn}`);
});

test('withExpiresIn: past date → negative day count (expired)', () => {
  const past = new Date(Date.now() - 5 * 86_400_000).toISOString();
  const r = withExpiresIn(whois({ expiryDate: past }));
  assert.ok(r.expiresIn != null && r.expiresIn < 0, `expected negative, got ${r.expiresIn}`);
});
