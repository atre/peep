import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseSpf, parseDmarc } from '../src/scanners/dns.js';
import { emailAuthChecks } from '../src/utils.js';
import { evaluateCheck } from '../src/commands/check.js';
import type { DnsResult, ScanResult } from '../src/types.js';

function dns(over: Partial<DnsResult> = {}): DnsResult {
  return {
    a: [], aaaa: [], mx: [], txt: [], ns: [], cname: [],
    googleVerification: null, microsoftVerification: null, facebookVerification: null,
    spf: null, dmarc: null, caa: [],
    ...over,
  };
}

function scan(over: Partial<ScanResult> = {}): ScanResult {
  return {
    domain: 'example.com', url: 'https://example.com', timestamp: '', duration: 0, isNoindex: false,
    dns: null, http: null, tls: null, whois: null, html: null, analytics: null, assets: null,
    robots: null, content: null, security: { score: 80, headers: [], formProviders: [] }, seo: null, tech: null, errors: [],
    ...over,
  };
}

// ── SPF parsing ──

test('parseSpf: includes, ip4/ip6, qualifiers and -all', () => {
  const r = parseSpf('v=spf1 include:_spf.google.com ip4:203.0.113.10 ip6:2001:db8::/32 +include:spf.mailer.example -all');
  assert.deepEqual(r.includes, ['_spf.google.com', 'spf.mailer.example']);
  assert.deepEqual(r.ip4, ['203.0.113.10']);
  assert.deepEqual(r.ip6, ['2001:db8::/32']);
  assert.equal(r.all, '-all');
  assert.equal(r.redirect, null);
});

test('parseSpf: ~all / ?all / +all and redirect=', () => {
  assert.equal(parseSpf('v=spf1 include:x.example ~all').all, '~all');
  assert.equal(parseSpf('v=spf1 ?all').all, '?all');
  assert.equal(parseSpf('v=spf1 +all').all, '+all');
  assert.equal(parseSpf('v=spf1 all').all, '+all', 'bare "all" is +all per RFC 7208');
  const red = parseSpf('v=spf1 redirect=_spf.example.net');
  assert.equal(red.redirect, '_spf.example.net');
  assert.equal(red.all, null);
});

// ── DMARC parsing ──

test('parseDmarc: policy, sp, pct, rua/ruf with mailto: and size limits stripped', () => {
  const r = parseDmarc('v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com!10m,mailto:re+abc@dmarc.postmarkapp.com; ruf=mailto:forensic@example.com');
  assert.equal(r.policy, 'reject');
  assert.equal(r.subdomainPolicy, 'quarantine');
  assert.equal(r.pct, 100);
  assert.deepEqual(r.rua, ['dmarc@example.com', 're+abc@dmarc.postmarkapp.com']);
  assert.deepEqual(r.ruf, ['forensic@example.com']);
});

test('parseDmarc: p=none, missing rua', () => {
  const r = parseDmarc('v=DMARC1; p=none');
  assert.equal(r.policy, 'none');
  assert.deepEqual(r.rua, []);
  assert.equal(r.pct, null);
});

// ── emailAuthChecks ──

test('emailAuthChecks: null when dns scanner did not run or is a pre-0.2 JSON', () => {
  assert.equal(emailAuthChecks(null), null);
  const legacy = dns(); delete (legacy as Partial<DnsResult>).spf; delete (legacy as Partial<DnsResult>).dmarc;
  assert.equal(emailAuthChecks(legacy), null, 'old JSON without the fields must not read as "missing"');
});

test('emailAuthChecks: no SPF + no DMARC → both missing, DKIM warning (none probed)', () => {
  const checks = emailAuthChecks(dns())!;
  assert.deepEqual(checks.map((c) => [c.name, c.rating]), [['SPF', 'missing'], ['DMARC', 'missing'], ['DKIM', 'warning']]);
});

test('emailAuthChecks: -all + p=reject → both good', () => {
  const checks = emailAuthChecks(dns({
    spf: parseSpf('v=spf1 include:_spf.google.com -all'),
    dmarc: parseDmarc('v=DMARC1; p=reject; rua=mailto:d@example.com'),
  }))!;
  assert.deepEqual(checks.map((c) => c.rating), ['good', 'good', 'warning']);
  assert.match(checks[0].value, /-all · include: _spf\.google\.com/);
  assert.match(checks[1].value, /p=reject rua=d@example\.com/);
});

// ── DKIM (informational) ──

test('emailAuthChecks: DKIM found at a probed selector → good, DMARC p=none hints "safe to move to p=quarantine"', () => {
  const checks = emailAuthChecks(dns({
    spf: parseSpf('v=spf1 -all'),
    dmarc: parseDmarc('v=DMARC1; p=none'),
    dkim: [{ selector: 'google', raw: 'v=DKIM1; p=abc' }],
  }))!;
  const dkim = checks.find((c) => c.name === 'DKIM')!;
  assert.equal(dkim.rating, 'good');
  assert.equal(dkim.value, 'google');
  const dmarc = checks.find((c) => c.name === 'DMARC')!;
  assert.match(dmarc.detail, /safe to move to p=quarantine/);
});

test('DKIM does not fail evaluateCheck --require-email-auth (informational only)', () => {
  const r = evaluateCheck('example.com', scan({
    dns: dns({ spf: parseSpf('v=spf1 -all'), dmarc: parseDmarc('v=DMARC1; p=reject') }),
  }), {}, { clusterOverride: null, securityThreshold: 50, requireSecurityTxt: false, expectNoindex: false, requireEmailAuth: true });
  assert.ok(!r.failures.some((f) => f.startsWith('DKIM')), 'DKIM must not fail --require-email-auth — it is informational only');
});

test('emailAuthChecks: +all is bad, ?all is warning, p=none is warning, pct<100 is warning', () => {
  assert.equal(emailAuthChecks(dns({ spf: parseSpf('v=spf1 +all') }))![0].rating, 'bad');
  assert.equal(emailAuthChecks(dns({ spf: parseSpf('v=spf1 include:x ?all') }))![0].rating, 'warning');
  assert.equal(emailAuthChecks(dns({ dmarc: parseDmarc('v=DMARC1; p=none') }))![1].rating, 'warning');
  assert.equal(emailAuthChecks(dns({ dmarc: parseDmarc('v=DMARC1; p=reject; pct=50') }))![1].rating, 'warning');
});

// ── check --require-email-auth ──

const gate = { clusterOverride: null, securityThreshold: 50, requireSecurityTxt: false, expectNoindex: false, requireEmailAuth: true };

test('check --require-email-auth: fails on missing SPF/DMARC, names both', () => {
  const r = evaluateCheck('example.com', scan({ dns: dns() }), {}, gate);
  assert.equal(r.failures.length, 2);
  assert.match(r.failures[0], /^SPF missing/);
  assert.match(r.failures[1], /^DMARC missing/);
});

test('check --require-email-auth: p=none is a failure (weak), -all + reject passes', () => {
  const weak = evaluateCheck('example.com', scan({ dns: dns({ spf: parseSpf('v=spf1 -all'), dmarc: parseDmarc('v=DMARC1; p=none') }) }), {}, gate);
  assert.equal(weak.failures.length, 1);
  assert.match(weak.failures[0], /^DMARC weak/);
  const ok = evaluateCheck('example.com', scan({ dns: dns({ spf: parseSpf('v=spf1 -all'), dmarc: parseDmarc('v=DMARC1; p=reject') }) }), {}, gate);
  assert.deepEqual(ok.failures, []);
});

test('check --require-email-auth: dns excluded by --only → note, not failure', () => {
  const r = evaluateCheck('example.com', scan(), {}, { ...gate, only: ['http'] });
  assert.deepEqual(r.failures, []);
  assert.ok(r.notes.some((n) => /email auth not checked/.test(n)));
});

test('check without --require-email-auth ignores email posture entirely', () => {
  const r = evaluateCheck('example.com', scan({ dns: dns() }), {}, { ...gate, requireEmailAuth: false });
  assert.deepEqual(r.failures, []);
});
