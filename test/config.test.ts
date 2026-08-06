import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { loadConfig } from '../src/config.js';

test('defaults applied when no file', () => {
  // Load config from a path that doesn't exist — should get defaults
  const c = loadConfig('/nonexistent/path/that/does/not/exist/.peeprc');
  assert.equal(c.thresholds.adultScore, 30);
  assert.equal(c.thresholds.correlationWarning, 40);
  assert.equal(c.scanning.concurrency, 5);
  assert.equal(c.scanning.timeout, 15000);
  assert.deepEqual(c.fleet.domains, []);
});

test('config file values override defaults', () => {
  const dir = mkdtempSync(join(tmpdir(), 'peep-test-'));
  const configPath = join(dir, '.peeprc');
  writeFileSync(configPath, JSON.stringify({
    thresholds: { adultScore: 50 },
    scanning: { concurrency: 10 },
  }));
  const c = loadConfig(configPath);
  assert.equal(c.thresholds.adultScore, 50);
  assert.equal(c.scanning.concurrency, 10);
  // Non-overridden values should be defaults
  assert.equal(c.thresholds.correlationWarning, 40);
  unlinkSync(configPath);
});

test('auto-merge clusters → domains when domains is empty', () => {
  const dir = mkdtempSync(join(tmpdir(), 'peep-test-'));
  const configPath = join(dir, '.peeprc');
  writeFileSync(configPath, JSON.stringify({
    fleet: {
      clusters: {
        'clean-1': ['a.com', 'b.com'],
        'adult-1': ['c.com'],
      },
    },
  }));
  const c = loadConfig(configPath);
  assert.ok(c.fleet.domains.includes('a.com'));
  assert.ok(c.fleet.domains.includes('b.com'));
  assert.ok(c.fleet.domains.includes('c.com'));
  assert.equal(c.fleet.domains.length, 3);
  unlinkSync(configPath);
});

test('domains not auto-populated when already set', () => {
  const dir = mkdtempSync(join(tmpdir(), 'peep-test-'));
  const configPath = join(dir, '.peeprc');
  writeFileSync(configPath, JSON.stringify({
    fleet: {
      domains: ['x.com'],
      clusters: {
        'clean-1': ['a.com', 'b.com'],
      },
    },
  }));
  const c = loadConfig(configPath);
  // domains was set, should not be merged from clusters
  assert.deepEqual(c.fleet.domains, ['x.com']);
  unlinkSync(configPath);
});

test('threshold values propagated', () => {
  const dir = mkdtempSync(join(tmpdir(), 'peep-test-'));
  const configPath = join(dir, '.peeprc');
  writeFileSync(configPath, JSON.stringify({
    thresholds: {
      adultScore: 40,
      correlationWarning: 50,
      correlationCritical: 80,
    },
  }));
  const c = loadConfig(configPath);
  assert.equal(c.thresholds.adultScore, 40);
  assert.equal(c.thresholds.correlationWarning, 50);
  assert.equal(c.thresholds.correlationCritical, 80);
  unlinkSync(configPath);
});

test('domain normalization in config', () => {
  const dir = mkdtempSync(join(tmpdir(), 'peep-test-'));
  const configPath = join(dir, '.peeprc');
  writeFileSync(configPath, JSON.stringify({
    fleet: {
      domains: ['https://example.com/', 'http://ANOTHER.COM/'],
    },
  }));
  const c = loadConfig(configPath);
  assert.ok(c.fleet.domains.includes('example.com'), `Expected 'example.com' in ${c.fleet.domains}`);
  assert.ok(c.fleet.domains.includes('another.com'), `Expected 'another.com' in ${c.fleet.domains}`);
  unlinkSync(configPath);
});
