import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

/**
 * Shared per-repo fleet config, also read by looksy/texter/trusty — the schema
 * is exactly these four keys. peep consumes `domains` and `pages`; `locales`
 * and `viewports` are ignored (other tools' concern).
 */
export interface FleetFile {
  domains: string[];
  pages: string[];
  locales: string[];
  viewports: string[];
}

const FLEET_KEYS = new Set<keyof FleetFile>(['domains', 'pages', 'locales', 'viewports']);

/**
 * Minimal zero-dep YAML subset: top-level `key: [a, b]` flow lists and
 * `key:` + indented `- item` block lists only. No nesting, no anchors, no
 * scalars — anything else on a recognized key's line resets that key.
 */
export function parseFleetYaml(text: string): FleetFile {
  const result: FleetFile = { domains: [], pages: [], locales: [], viewports: [] };
  let currentKey: keyof FleetFile | null = null;

  for (const rawLine of text.split(/\r?\n/)) {
    if (!rawLine.trim()) continue;

    const blockItem = /^\s*-\s*(.+)$/.exec(rawLine);
    if (blockItem && currentKey) {
      result[currentKey].push(blockItem[1].trim());
      continue;
    }

    const kv = /^(\w+):\s*(.*)$/.exec(rawLine);
    if (!kv) { currentKey = null; continue; }
    const [, key, rest] = kv;
    if (!FLEET_KEYS.has(key as keyof FleetFile)) { currentKey = null; continue; }
    const fleetKey = key as keyof FleetFile;
    const value = rest.trim();

    if (value.startsWith('[') && value.endsWith(']')) {
      result[fleetKey] = value.slice(1, -1).split(',').map((s) => s.trim()).filter(Boolean);
      currentKey = null;
    } else if (value === '') {
      currentKey = fleetKey; // block list follows on subsequent `- item` lines
    } else {
      currentKey = null;
    }
  }

  return result;
}

/** Load `fleet.yaml` from the given path, or `./fleet.yaml` by default.
 *  Returns null when the file doesn't exist or fails to parse — a missing
 *  fleet file is the common case, not an error. */
export function loadFleetFile(path?: string): FleetFile | null {
  const p = resolve(process.cwd(), path || 'fleet.yaml');
  if (!existsSync(p)) return null;
  try {
    return parseFleetYaml(readFileSync(p, 'utf-8'));
  } catch {
    return null;
  }
}
