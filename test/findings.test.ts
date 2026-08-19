import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toFindings } from '../src/findings.js';
import { parseDmarc } from '../src/scanners/dns.js';
import type { DnsResult, ScanResult, SecurityHeader, SeoCheck } from '../src/types.js';

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
    robots: null, content: null, security: null, seo: null, tech: null, errors: [],
    ...over,
  };
}

const cspMissing: SecurityHeader = { name: 'Content-Security-Policy', present: false, value: null, rating: 'missing', detail: 'No CSP — vulnerable to XSS' };
const hstsGood: SecurityHeader = { name: 'Strict-Transport-Security', present: true, value: 'max-age=63072000', rating: 'good', detail: 'HSTS set' };
const ogWarning: SeoCheck = { name: 'Open Graph', present: true, value: '3/4', rating: 'warning', detail: 'Missing: og:image' };
const titleGood: SeoCheck = { name: 'Title', present: true, value: '40 chars', rating: 'good', detail: 'optimal' };

test('missing security header → crit finding; DMARC p=none → warn finding; good checks produce nothing', () => {
  const findings = toFindings(scan({
    security: { score: 50, headers: [cspMissing, hstsGood], formProviders: [] },
    dns: dns({ spf: { raw: '', includes: [], ip4: [], ip6: [], redirect: null, all: '-all' }, dmarc: parseDmarc('v=DMARC1; p=none') }),
  }));
  const sec = findings.find((f) => f.id === 'sec:example.com/content-security-policy');
  assert.ok(sec, 'expected sec:example.com/content-security-policy');
  assert.equal(sec!.severity, 'crit');
  assert.equal(sec!.scope, 'site');
  assert.equal(sec!.hint, 'peep scan example.com --only security');

  const email = findings.find((f) => f.id === 'email:example.com/dmarc');
  assert.ok(email, 'expected email:example.com/dmarc');
  assert.equal(email!.severity, 'warn');
  assert.equal(email!.hint, 'peep scan example.com --only dns');

  assert.ok(!findings.some((f) => f.id.includes('strict-transport-security')), 'good header must not produce a finding');
  assert.ok(!findings.some((f) => f.id.includes('/spf')), 'good SPF must not produce a finding');
});

test('SEO warning check → warn finding; good SEO check produces nothing', () => {
  const findings = toFindings(scan({ seo: { score: 90, checks: [ogWarning, titleGood], evaluated: 2, total: 12 } }));
  const seo = findings.find((f) => f.id === 'seo:example.com/open-graph');
  assert.ok(seo);
  assert.equal(seo!.severity, 'warn');
  assert.equal(seo!.hint, 'peep scan example.com --only seo');
  assert.ok(!findings.some((f) => f.id.includes('/title')));
});

test('empty scan → no findings', () => {
  assert.deepEqual(toFindings(scan()), []);
});

test('explicit http:// target → no email-auth crit findings, even with missing SPF/DMARC', () => {
  const findings = toFindings(scan({
    url: 'http://localhost:9999',
    dns: dns(), // spf: null, dmarc: null — on a real https target this is 2 crit findings
  }));
  assert.deepEqual(findings.filter((f) => f.id.startsWith('email:')), []);
});

test('real https target with the same missing SPF/DMARC still fires the crit findings (regression guard)', () => {
  const findings = toFindings(scan({ dns: dns() }));
  assert.ok(findings.some((f) => f.id === 'email:example.com/spf' && f.severity === 'crit'));
  assert.ok(findings.some((f) => f.id === 'email:example.com/dmarc' && f.severity === 'crit'));
});
