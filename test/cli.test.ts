import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs } from '../src/cli.js';
import { normalizeDomain } from '../src/utils.js';

function args(...a: string[]): string[] {
  return ['node', 'peep', ...a];
}

test('scan example.com → correct command and domain', () => {
  const r = parseArgs(args('scan', 'example.com'));
  assert.equal(r.command, 'scan');
  assert.deepEqual(r.domains, ['example.com']);
});

test('fleet command', () => {
  const r = parseArgs(args('fleet'));
  assert.equal(r.command, 'fleet');
});

test('fleet --skip-whois → correct flag', () => {
  const r = parseArgs(args('fleet', '--skip-whois'));
  assert.equal(r.command, 'fleet');
  assert.equal(r.flags['skip-whois'], true);
});

test('-j shorthand sets format=json', () => {
  const r = parseArgs(args('scan', 'example.com', '-j'));
  assert.equal(r.flags.format, 'json');
});

test('--format json sets format', () => {
  const r = parseArgs(args('scan', 'example.com', '--format', 'json'));
  assert.equal(r.flags.format, 'json');
});

test('--only dns,tls → correct filter', () => {
  const r = parseArgs(args('scan', 'example.com', '--only', 'dns,tls'));
  assert.equal(r.flags.only, 'dns,tls');
});

test('-v sets verbose flag', () => {
  const r = parseArgs(args('scan', 'example.com', '-v'));
  assert.equal(r.flags.verbose, true);
});

test('-q sets quiet flag', () => {
  const r = parseArgs(args('fleet', '-q'));
  assert.equal(r.flags.quiet, true);
});

test('multiple domains parsed', () => {
  const r = parseArgs(args('scan', 'a.com', 'b.com', 'c.com'));
  assert.equal(r.command, 'scan');
  assert.deepEqual(r.domains, ['a.com', 'b.com', 'c.com']);
});

test('normalizeDomain strips https:// prefix', () => {
  assert.equal(normalizeDomain('https://example.com'), 'example.com');
});

test('normalizeDomain strips http:// prefix', () => {
  assert.equal(normalizeDomain('http://example.com'), 'example.com');
});

test('normalizeDomain strips trailing slashes', () => {
  assert.equal(normalizeDomain('example.com/'), 'example.com');
});

test('check command parsed', () => {
  const r = parseArgs(args('check', 'example.com'));
  assert.equal(r.command, 'check');
  assert.deepEqual(r.domains, ['example.com']);
});

test('diff command parsed', () => {
  const r = parseArgs(args('diff'));
  assert.equal(r.command, 'diff');
});

// ── --dns <server>: value must not be swallowed as a domain (IPs contain dots) ──

test('--dns 1.1.1.1 example.com → dns flag takes the IP, domain list unaffected', () => {
  const r = parseArgs(args('scan', 'example.com', '--dns', '1.1.1.1'));
  assert.equal(r.flags.dns, '1.1.1.1');
  assert.deepEqual(r.domains, ['example.com']);
});

test('--dns before the domain also parses correctly', () => {
  const r = parseArgs(args('scan', '--dns', '9.9.9.9', 'example.com'));
  assert.equal(r.flags.dns, '9.9.9.9');
  assert.deepEqual(r.domains, ['example.com']);
});

test('--prelaunch is a boolean flag', () => {
  const r = parseArgs(args('check', 'example.com', '--prelaunch'));
  assert.equal(r.flags.prelaunch, true);
});

test('--expect noindex takes a string value', () => {
  const r = parseArgs(args('check', 'example.com', '--expect', 'noindex'));
  assert.equal(r.flags.expect, 'noindex');
});

test('no command → help', () => {
  const r = parseArgs(args());
  assert.equal(r.command, 'help');
});
