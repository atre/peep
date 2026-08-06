import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { PeepConfig } from './types.js';
import { normalizeDomain } from './utils.js';

const DEFAULTS: PeepConfig = {
  fleet: {
    domains: [],
    clusters: {},
  },
  thresholds: {
    adultScore: 30,
    correlationWarning: 40,
    correlationCritical: 70,
  },
  scanning: {
    concurrency: 5,
    timeout: 15000,
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    followRedirects: true,
    whoisEnabled: true,
    hashContent: true,
  },
};

export function loadConfig(customPath?: string): PeepConfig {
  const paths = customPath
    ? [customPath]
    : [
        resolve(process.cwd(), '.peeprc'),
        resolve(process.cwd(), '.peeprc.json'),
        resolve(process.env.HOME || '~', '.peeprc'),
      ];

  for (const p of paths) {
    if (existsSync(p)) {
      try {
        const raw = readFileSync(p, 'utf-8');
        const parsed = JSON.parse(raw);
        return postProcess(merge(DEFAULTS, parsed));
      } catch (e) {
        console.error(`Warning: failed to parse config at ${p}: ${(e as Error).message}`);
      }
    }
  }

  return postProcess(DEFAULTS);
}

// Keys that must never leak into merged config (prototype pollution prevention)
const BANNED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function sanitize<T extends Record<string, unknown>>(obj: T): T {
  for (const key of BANNED_KEYS) {
    if (key in obj) delete (obj as Record<string, unknown>)[key];
  }
  return obj;
}

function postProcess(config: PeepConfig): PeepConfig {
  // Normalize all domain entries
  const normalizedDomains = config.fleet.domains.map(normalizeDomain);

  // Normalize cluster entries
  const normalizedClusters: Record<string, string[]> = {};
  for (const [name, domains] of Object.entries(config.fleet.clusters)) {
    if (BANNED_KEYS.has(name)) continue;
    normalizedClusters[name] = domains.map(normalizeDomain);
  }

  // Auto-merge clusters → domains if domains list is empty
  const finalDomains = [...normalizedDomains];
  if (finalDomains.length === 0 && Object.keys(normalizedClusters).length > 0) {
    const seen = new Set<string>();
    for (const domains of Object.values(normalizedClusters)) {
      for (const d of domains) {
        if (!seen.has(d)) {
          seen.add(d);
          finalDomains.push(d);
        }
      }
    }
  }

  return {
    ...config,
    fleet: {
      domains: finalDomains,
      clusters: normalizedClusters,
    },
  };
}

function merge(defaults: PeepConfig, overrides: Partial<PeepConfig>): PeepConfig {
  return {
    fleet: sanitize({ ...defaults.fleet, ...overrides.fleet }),
    thresholds: sanitize({ ...defaults.thresholds, ...overrides.thresholds }),
    scanning: sanitize({ ...defaults.scanning, ...overrides.scanning }),
  };
}
