import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isNxdomainLike,
  staleResolverWarning,
  decideResolution,
  withResolverWarning,
  DEFAULT_PUBLIC_RESOLVER,
} from '../src/resolver.js';

// ── isNxdomainLike ──

test('isNxdomainLike: ENOTFOUND and ENODATA are NXDOMAIN-shaped', () => {
  assert.equal(isNxdomainLike('ENOTFOUND'), true);
  assert.equal(isNxdomainLike('ENODATA'), true);
});

test('isNxdomainLike: other error codes are not (a timeout can\'t be contradicted by a 2nd resolver)', () => {
  assert.equal(isNxdomainLike('ETIMEDOUT'), false);
  assert.equal(isNxdomainLike('ECONNREFUSED'), false);
  assert.equal(isNxdomainLike(null), false);
  assert.equal(isNxdomainLike(undefined), false);
});

// ── staleResolverWarning ──

test('staleResolverWarning: matches the reported incident phrasing', () => {
  const msg = staleResolverWarning('1.1.1.1', ['203.0.113.5']);
  assert.match(msg, /local resolver returned NXDOMAIN but 1\.1\.1\.1 resolves/);
  assert.match(msg, /retry with --dns 1\.1\.1\.1/);
  assert.match(msg, /203\.0\.113\.5/);
});

// ── decideResolution: the core "same code path" decision ──

test('decideResolution: OS error not NXDOMAIN-shaped → never acts, regardless of --dns', () => {
  const r = decideResolution('ETIMEDOUT', ['203.0.113.5'], DEFAULT_PUBLIC_RESOLVER, true);
  assert.deepEqual(r, { addresses: [], warning: null });
});

test('decideResolution: both OS and public resolver agree (public empty too) → silent, no warning', () => {
  const r = decideResolution('ENOTFOUND', [], DEFAULT_PUBLIC_RESOLVER, false);
  assert.deepEqual(r, { addresses: [], warning: null }, 'a genuine NXDOMAIN both resolvers agree on needs no commentary');
});

test('decideResolution: disagreement, no --dns given → warning only, no addresses (default never silently overrides)', () => {
  const r = decideResolution('ENOTFOUND', ['203.0.113.5'], '1.1.1.1', false);
  assert.deepEqual(r.addresses, []);
  assert.ok(r.warning);
  assert.match(r.warning!, /retry with --dns 1\.1\.1\.1/);
});

test('decideResolution: disagreement, --dns explicitly given → uses the public answer, no warning needed', () => {
  const r = decideResolution('ENOTFOUND', ['203.0.113.5'], '1.1.1.1', true);
  assert.deepEqual(r.addresses, ['203.0.113.5']);
  assert.equal(r.warning, null);
});

// ── withResolverWarning ──

test('withResolverWarning: appends the warning to the error message when present', () => {
  const err = new Error('getaddrinfo ENOTFOUND example.com') as Error & { peepResolverWarning?: string };
  err.peepResolverWarning = 'local resolver returned NXDOMAIN but 1.1.1.1 resolves — likely stale negative cache; retry with --dns 1.1.1.1';
  const out = withResolverWarning(err);
  assert.equal(out, err, 'mutates and returns the same error');
  assert.match(out.message, /ENOTFOUND example\.com — local resolver returned NXDOMAIN/);
});

test('withResolverWarning: no-op when there is no warning attached', () => {
  const err = new Error('getaddrinfo ENOTFOUND example.com');
  const out = withResolverWarning(err);
  assert.equal(out.message, 'getaddrinfo ENOTFOUND example.com');
});

test('withResolverWarning: reads the warning off err.cause — fetch() wraps dns.lookup() errors as "fetch failed" with the real error as .cause', () => {
  const cause = new Error('getaddrinfo ENOTFOUND example.com') as Error & { peepResolverWarning?: string };
  cause.peepResolverWarning = 'local resolver returned NXDOMAIN but 1.1.1.1 resolves (203.0.113.5) — likely stale negative cache; retry with --dns 1.1.1.1';
  const wrapped = new TypeError('fetch failed', { cause });
  const out = withResolverWarning(wrapped);
  assert.match(out.message, /fetch failed — local resolver returned NXDOMAIN but 1\.1\.1\.1 resolves/);
});
