import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFleetYaml } from '../src/fleet-config.js';
import { parseArgs } from '../src/cli.js';

test('parseFleetYaml: flow lists and block lists for all four keys', () => {
  const r = parseFleetYaml('domains: [a.com, b.com]\npages:\n  - /\n  - /about\nlocales: [en, de]\nviewports: [mobile, desktop]\n');
  assert.deepEqual(r, { domains: ['a.com', 'b.com'], pages: ['/', '/about'], locales: ['en', 'de'], viewports: ['mobile', 'desktop'] });
});

test('parseFleetYaml: empty input → all keys empty', () => {
  assert.deepEqual(parseFleetYaml(''), { domains: [], pages: [], locales: [], viewports: [] });
});

test('parseFleetYaml: unrecognized key is ignored, does not leak into a block list', () => {
  const r = parseFleetYaml('unknown:\n  - x\ndomains: [a.com]\n');
  assert.deepEqual(r.domains, ['a.com']);
});

test('--fleet <path> flag parses', () => {
  const r = parseArgs(['node', 'peep', 'check', 'a.com', '--fleet', 'x/fleet.yaml']);
  assert.equal(r.flags.fleet, 'x/fleet.yaml');
});
