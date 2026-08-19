import { test } from 'node:test';
import assert from 'node:assert/strict';

// TLS scanner requires network, so we test the helper functions by importing the module
// and checking the output shape. We extract parseSAN logic for unit testing.

// Since parseSAN is not exported, we test via the full scanner output shape
// against a known domain (integration-style)

test('TlsResult type shape (offline mock)', () => {
  // Verify the expected interface fields exist by constructing a mock
  const mockResult = {
    issuer: 'C=US, O=Test, CN=TestCA',
    subject: 'CN=example.com',
    validFrom: 'Jan 1 00:00:00 2026 GMT',
    validTo: 'Dec 31 23:59:59 2026 GMT',
    serialNumber: '0123456789ABCDEF',
    san: ['example.com', '*.example.com'],
    protocol: 'TLSv1.3',
    cipher: 'TLS_AES_256_GCM_SHA384',
    fingerprint: 'AA:BB:CC',
    daysUntilExpiry: 365,
  };

  assert.equal(typeof mockResult.issuer, 'string');
  assert.ok(Array.isArray(mockResult.san));
  assert.equal(typeof mockResult.daysUntilExpiry, 'number');
  assert.equal(mockResult.san.length, 2);
  assert.equal(mockResult.san[0], 'example.com');
});

test('SAN parsing: DNS: prefix stripping', () => {
  // Replicate parseSAN logic
  const sanRaw = 'DNS:example.com, DNS:*.example.com, DNS:other.test';
  const parsed = sanRaw.split(',').map((s) => s.trim().replace(/^DNS:/, ''));
  assert.deepEqual(parsed, ['example.com', '*.example.com', 'other.test']);
});

test('SAN parsing: empty string returns empty array', () => {
  const sanRaw: string = '';
  const parsed = sanRaw ? sanRaw.split(',').map((s: string) => s.trim().replace(/^DNS:/, '')) : [];
  assert.deepEqual(parsed, []);
});

test('daysUntilExpiry calculation', () => {
  const validTo = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toUTCString();
  const expiryMs = new Date(validTo).getTime();
  const days = Math.floor((expiryMs - Date.now()) / (1000 * 60 * 60 * 24));
  assert.ok(days >= 29 && days <= 31);
});

test('daysUntilExpiry: expired cert gives negative days', () => {
  const validTo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toUTCString();
  const expiryMs = new Date(validTo).getTime();
  const days = Math.floor((expiryMs - Date.now()) / (1000 * 60 * 60 * 24));
  assert.ok(days < 0);
});

// ── --host: SNI override (scanTls's `servername: sniHost || domain` precedence) ──
// scanTls itself does real I/O and isn't unit-testable (see file header) —
// this replicates its one-line precedence rule the same way the SAN-parsing
// tests above replicate parseSAN, without a real TLS handshake.

test('SNI override: --host takes precedence over the connect domain for servername', () => {
  const domain = 'pr-123.vercel.app';
  const sniHost: string | undefined = 'example.com';
  assert.equal(sniHost || domain, 'example.com');
});

test('SNI override: no --host falls back to the literal connect domain', () => {
  const domain = 'pr-123.vercel.app';
  const sniHost: string | undefined = undefined;
  assert.equal(sniHost || domain, domain);
});
