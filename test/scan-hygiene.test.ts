import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanDomain } from '../src/scanners/index.js';
import { whoisStatusLine, tlsStatusLine } from '../src/commands/scan.js';
import { EXPLICIT_HTTP_TARGET_SKIP_REASON, isExplicitHttpTarget } from '../src/utils.js';
import type { ScanResult, ScanningConfig } from '../src/types.js';

function scan(over: Partial<ScanResult> = {}): ScanResult {
  return {
    domain: 'localhost:9999', url: 'http://localhost:9999', timestamp: '', duration: 0, isNoindex: false,
    dns: null, http: null, tls: null, whois: null, html: null, analytics: null, assets: null,
    robots: null, content: null, security: null, seo: null, tech: null, errors: [],
    ...over,
  };
}

const baseConfig: ScanningConfig = {
  concurrency: 5, timeout: 100, userAgent: 'peep/test', followRedirects: true, whoisEnabled: true, hashContent: false,
};

// ── Part A/B: scanDomain skips TLS + WHOIS outright for an explicit http:// target ──
//
// `--only tls,whois` selects no dns/http-dependent scanner, so with the skip
// branch taken (scheme: 'http') scanDomain performs zero network I/O here —
// safe to call the real function rather than mocking it.

test('scanDomain: explicit http:// target skips TLS with the exact reason string, tls stays null', async () => {
  const result = await scanDomain('localhost:9999', {
    config: { ...baseConfig, scheme: 'http' },
    only: ['tls', 'whois'],
  });
  assert.equal(result.tls, null);
  assert.equal(result.errors.find((e) => e.scanner === 'tls')?.error, EXPLICIT_HTTP_TARGET_SKIP_REASON);
});

test('scanDomain: explicit http:// target skips WHOIS with the exact reason string, whois stays null', async () => {
  const result = await scanDomain('localhost:9999', {
    config: { ...baseConfig, scheme: 'http' },
    only: ['tls', 'whois'],
  });
  assert.equal(result.whois, null);
  assert.equal(result.errors.find((e) => e.scanner === 'whois')?.error, EXPLICIT_HTTP_TARGET_SKIP_REASON);
});

test('scanDomain: --skip-whois still wins over the http-target skip (still records its own reason, not the http-target one)', async () => {
  const result = await scanDomain('localhost:9999', {
    config: { ...baseConfig, scheme: 'http' },
    only: ['whois'],
    skipWhois: true,
  });
  assert.equal(result.errors.find((e) => e.scanner === 'whois')?.error, 'skipped — --skip-whois overrides --only whois');
});

// ── Text renderer: TLS/WHOIS status lines ──

test('whoisStatusLine: explicit http:// skip reason renders as "WHOIS: skipped (...)", not "unavailable (...)"', () => {
  const line = whoisStatusLine(scan({ errors: [{ scanner: 'whois', error: EXPLICIT_HTTP_TARGET_SKIP_REASON }] }));
  assert.equal(line, `WHOIS: ${EXPLICIT_HTTP_TARGET_SKIP_REASON}`);
});

test('whoisStatusLine: a real lookup failure keeps the existing "unavailable (...)" wording', () => {
  const line = whoisStatusLine(scan({ errors: [{ scanner: 'whois', error: 'whois binary not found' }] }));
  assert.equal(line, 'WHOIS: unavailable (whois binary not found)');
});

test('tlsStatusLine: explicit http:// skip reason renders as "TLS: skipped (...)"', () => {
  const line = tlsStatusLine(scan({ errors: [{ scanner: 'tls', error: EXPLICIT_HTTP_TARGET_SKIP_REASON }] }));
  assert.equal(line, `TLS: ${EXPLICIT_HTTP_TARGET_SKIP_REASON}`);
});

test('tlsStatusLine: a real TLS failure (not the skip reason) prints nothing — unchanged prior behavior', () => {
  const line = tlsStatusLine(scan({ errors: [{ scanner: 'tls', error: 'connect ECONNREFUSED' }] }));
  assert.equal(line, null);
});

test('tlsStatusLine: tls populated → no status line', () => {
  const line = tlsStatusLine(scan({
    tls: { issuer: '', subject: '', validFrom: '', validTo: '', serialNumber: '', san: [], protocol: '', cipher: '', fingerprint: '', daysUntilExpiry: null },
  }));
  assert.equal(line, null);
});

test('tlsStatusLine: tls not selected via --only → no status line', () => {
  const line = tlsStatusLine(scan({ errors: [{ scanner: 'tls', error: EXPLICIT_HTTP_TARGET_SKIP_REASON }] }), ['dns']);
  assert.equal(line, null);
});

// ── isExplicitHttpTarget ──

test('isExplicitHttpTarget: true for an http:// scan url', () => {
  assert.equal(isExplicitHttpTarget(scan({ url: 'http://localhost:9999' })), true);
});

test('isExplicitHttpTarget: false for an https:// scan url', () => {
  assert.equal(isExplicitHttpTarget(scan({ url: 'https://example.com' })), false);
});
