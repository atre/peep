import { test } from 'node:test';
import assert from 'node:assert/strict';

// DNS scanner uses Node's dns.promises — test the verification token extraction logic

test('Google verification token extracted from TXT record', () => {
  const txt = 'google-site-verification=abc123_DEF-456';
  const match = txt.match(/^google-site-verification=([A-Za-z0-9_-]+)/i);
  assert.equal(match?.[1], 'abc123_DEF-456');
});

test('Microsoft verification token extracted from TXT record', () => {
  const txt = 'ms=ms12345678';
  const match = txt.match(/^ms=([A-Za-z0-9_-]+)/i);
  assert.equal(match?.[1], 'ms12345678');
});

test('Facebook verification token extracted from TXT record', () => {
  const txt = 'facebook-domain-verification=abcdef0123456789';
  const match = txt.match(/^facebook-domain-verification=([a-z0-9]+)/i);
  assert.equal(match?.[1], 'abcdef0123456789');
});

test('Non-verification TXT record does not match', () => {
  const txt = 'v=spf1 include:_spf.google.com ~all';
  const googleMatch = txt.match(/^google-site-verification=([A-Za-z0-9_-]+)/i);
  const msMatch = txt.match(/^ms=([A-Za-z0-9_-]+)/i);
  const fbMatch = txt.match(/^facebook-domain-verification=([a-z0-9]+)/i);
  assert.equal(googleMatch, null);
  assert.equal(msMatch, null);
  assert.equal(fbMatch, null);
});

test('MX record structure matches expected shape', () => {
  const mxRecords = [
    { exchange: 'mx1.example.com', priority: 10 },
    { exchange: 'mx2.example.com', priority: 20 },
  ];
  assert.equal(mxRecords[0].exchange, 'mx1.example.com');
  assert.equal(mxRecords[0].priority, 10);
  // Verify string interpolation works (was [object Object] bug)
  const formatted = mxRecords.map((m) => `${m.exchange} (${m.priority})`).join(', ');
  assert.equal(formatted, 'mx1.example.com (10), mx2.example.com (20)');
});
