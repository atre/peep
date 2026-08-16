import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRequestHeaders } from '../src/scanners/http.js';
import type { ScanningConfig } from '../src/types.js';

const defaultConfig: ScanningConfig = {
  concurrency: 5,
  timeout: 8000,
  userAgent: 'peep/1.0',
  followRedirects: true,
  whoisEnabled: true,
  hashContent: false,
};

test('default config sends no Accept-Language', () => {
  const headers = buildRequestHeaders(defaultConfig);
  assert.equal('Accept-Language' in headers, false);
});

test('--lang de sets Accept-Language: de', () => {
  const headers = buildRequestHeaders({ ...defaultConfig, acceptLanguage: 'de' });
  assert.equal(headers['Accept-Language'], 'de');
});
