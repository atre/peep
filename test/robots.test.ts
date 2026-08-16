import { test } from 'node:test';
import assert from 'node:assert/strict';
import { summarizeRobotsTxt, summarizeSecurityTxt, summarizeHumansTxt } from '../src/scanners/robots.js';

test('robots.txt summary: Disallow / for all agents', () => {
  const s = summarizeRobotsTxt('User-agent: *\nDisallow: /\n');
  assert.equal(s.blocksAll, true);
  assert.deepEqual(s.blockedAgents, ['*']);
  assert.deepEqual(s.disallowPaths, []);
});

test('robots.txt summary: grouped agents, specific paths, comments ignored', () => {
  const s = summarizeRobotsTxt(`# comment
User-agent: GPTBot
User-agent: CCBot
Disallow: /

User-agent: *
Allow: /
Disallow: /admin/ # trailing comment
Disallow: /cart
Sitemap: https://example.com/sitemap.xml
`);
  assert.equal(s.blocksAll, false);
  assert.deepEqual(s.blockedAgents, ['GPTBot', 'CCBot']);
  assert.deepEqual(s.disallowPaths, ['/admin/', '/cart']);
  assert.equal(s.agentCount, 3);
});

test('security.txt summary: contacts, expiry, policy, signature', () => {
  const future = new Date(Date.now() + 200 * 86_400_000).toISOString();
  const s = summarizeSecurityTxt(`Contact: mailto:security@example.com\nContact: https://example.com/security\nExpires: ${future}\nPolicy: https://example.com/policy\n`);
  assert.deepEqual(s.contacts, ['mailto:security@example.com', 'https://example.com/security']);
  assert.equal(s.policy, 'https://example.com/policy');
  assert.ok(s.expiresInDays !== null && s.expiresInDays >= 199 && s.expiresInDays <= 200);
  assert.equal(s.hasSignature, false);
});

test('security.txt summary: expired and unparseable Expires', () => {
  assert.ok((summarizeSecurityTxt('Contact: mailto:a@b.c\nExpires: 2020-01-01T00:00:00.000Z').expiresInDays ?? 0) < 0);
  const bad = summarizeSecurityTxt('Contact: mailto:a@b.c\nExpires: soon');
  assert.equal(bad.expires, 'soon');
  assert.equal(bad.expiresInDays, null);
  assert.equal(summarizeSecurityTxt('Contact: mailto:a@b.c').expires, null);
});

test('summarizeHumansTxt: line count plus first Contact/team-lead value', () => {
  const s = summarizeHumansTxt('/* TEAM */\n  Chef: Jane\n  Contact: jane [at] x.com\n');
  assert.deepEqual(s, { lines: 3, contact: 'jane [at] x.com', team: 'Jane' });
});

test('summarizeHumansTxt: no Contact/team lines → nulls, blank lines not counted', () => {
  const s = summarizeHumansTxt('/* TEAM */\n\n  Site: example.com\n');
  assert.deepEqual(s, { lines: 2, contact: null, team: null });
});
