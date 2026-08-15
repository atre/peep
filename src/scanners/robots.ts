import { origin, shortHash } from '../utils.js';
import type { RobotsResult, ScanningConfig, RobotsTxtSummary, SecurityTxtSummary } from '../types.js';
import { readCapped } from '../fetch-guard.js';

const AFFILIATE_REDIRECT_PATHS = ['/go/', '/out/', '/redirect/', '/aff/', '/refer/'];

export async function scanRobots(domain: string, config: ScanningConfig): Promise<RobotsResult> {
  const result: RobotsResult = {
    robotsTxt: null,
    robotsTxtHash: null,
    sitemapUrls: [],
    sitemapHash: null,
    affiliateRedirectPaths: [],
    adsTxt: null,
    adsTxtHash: null,
    adsTxtPubIds: [],
    securityTxt: null,
    humansTxt: null,
  };

  const fetchFile = async (path: string): Promise<string | null> => {
    try {
      const resp = await fetch(`${origin(domain, config.scheme)}${path}`, {
        signal: AbortSignal.timeout(config.timeout),
        headers: { 'User-Agent': config.userAgent },
      });
      if (!resp.ok) return null;
      const text = await readCapped(resp);
      // Guard against HTML error pages
      if (text.trimStart().startsWith('<!') || text.trimStart().startsWith('<html')) return null;
      return text;
    } catch {
      return null;
    }
  };

  const [robots, ads, security, humans] = await Promise.all([
    fetchFile('/robots.txt'),
    fetchFile('/ads.txt'),
    fetchFile('/.well-known/security.txt'),
    fetchFile('/humans.txt'),
  ]);

  if (robots) {
    result.robotsTxt = robots;
    result.robotsTxtHash = shortHash(normalizeWhitespace(robots));
    result.robotsSummary = summarizeRobotsTxt(robots);
    // Extract sitemap URLs
    const sitemapRe = /Sitemap:\s*(\S+)/gi;
    let match: RegExpExecArray | null;
    while ((match = sitemapRe.exec(robots)) !== null) {
      if (match[1]) result.sitemapUrls.push(match[1]);
    }
    // Extract affiliate redirect paths from Disallow lines
    const disallowRe = /^Disallow:\s*(\S+)/gim;
    let dm: RegExpExecArray | null;
    while ((dm = disallowRe.exec(robots)) !== null) {
      const path = dm[1];
      if (path && AFFILIATE_REDIRECT_PATHS.some((p) => path.startsWith(p) || path === p.replace(/\/$/, ''))) {
        if (!result.affiliateRedirectPaths.includes(path)) {
          result.affiliateRedirectPaths.push(path);
        }
      }
    }
  }

  // Fetch and hash the first sitemap for structural comparison
  if (result.sitemapUrls.length > 0) {
    try {
      const sitemapContent = await fetchFile(new URL(result.sitemapUrls[0]).pathname);
      if (sitemapContent) {
        // Normalize: strip domain-specific URLs but keep XML structure/tags
        const normalized = sitemapContent
          .replace(/<loc>[^<]*<\/loc>/g, '<loc>URL</loc>')
          .replace(/<lastmod>[^<]*<\/lastmod>/g, '<lastmod>DATE</lastmod>');
        result.sitemapHash = shortHash(normalizeWhitespace(normalized));
      }
    } catch {
      // Sitemap fetch/parse failed — non-fatal
    }
  } else {
    // No sitemap in robots.txt — try default /sitemap.xml
    try {
      const sitemapContent = await fetchFile('/sitemap.xml');
      if (sitemapContent) {
        result.sitemapUrls.push(`${origin(domain, config.scheme)}/sitemap.xml`);
        const normalized = sitemapContent
          .replace(/<loc>[^<]*<\/loc>/g, '<loc>URL</loc>')
          .replace(/<lastmod>[^<]*<\/lastmod>/g, '<lastmod>DATE</lastmod>');
        result.sitemapHash = shortHash(normalizeWhitespace(normalized));
      }
    } catch {
      // No sitemap — that's fine
    }
  }

  if (ads) {
    result.adsTxt = ads;
    result.adsTxtHash = shortHash(normalizeWhitespace(ads));
    // Parse IAB ads.txt format: domain, pub-id, relationship[, cert-auth-id]
    const pubIds: string[] = [];
    for (const line of ads.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const parts = trimmed.split(',');
      if (parts.length >= 2) {
        const pubId = parts[1]?.trim();
        if (pubId && !pubIds.includes(pubId)) {
          pubIds.push(pubId);
        }
      }
    }
    result.adsTxtPubIds = pubIds;
  }

  result.securityTxt = security;
  result.humansTxt = humans;
  if (security) result.securityTxtSummary = summarizeSecurityTxt(security);

  return result;
}

/** Key facts of a robots.txt: which agents are fully blocked, what paths are disallowed. */
export function summarizeRobotsTxt(text: string): RobotsTxtSummary {
  const blockedAgents: string[] = [];
  const disallowPaths = new Set<string>();
  let agentCount = 0;
  let currentAgents: string[] = [];
  let sawDirective = false;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const value = m[2].trim();
    if (key === 'user-agent') {
      // Consecutive User-agent lines share one group; a new one after
      // directives starts a fresh group.
      if (sawDirective) { currentAgents = []; sawDirective = false; }
      currentAgents.push(value);
      agentCount++;
    } else if (key === 'disallow') {
      sawDirective = true;
      if (value === '/') {
        for (const a of currentAgents) if (!blockedAgents.includes(a)) blockedAgents.push(a);
      } else if (value) {
        disallowPaths.add(value);
      }
    } else if (key === 'allow' || key === 'crawl-delay') {
      sawDirective = true;
    }
  }

  return {
    blockedAgents,
    blocksAll: blockedAgents.includes('*'),
    disallowPaths: [...disallowPaths],
    agentCount,
  };
}

/** Key facts of a security.txt (RFC 9116): contacts, expiry, policy, signature. */
export function summarizeSecurityTxt(text: string): SecurityTxtSummary {
  const contacts: string[] = [];
  let expires: string | null = null;
  let policy: string | null = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^([A-Za-z-]+)\s*:\s*(.+)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const value = m[2].trim();
    if (key === 'contact') contacts.push(value);
    else if (key === 'expires' && !expires) expires = value;
    else if (key === 'policy' && !policy) policy = value;
  }
  let expiresInDays: number | null = null;
  if (expires) {
    const t = Date.parse(expires);
    if (!Number.isNaN(t)) expiresInDays = Math.floor((t - Date.now()) / 86_400_000);
  }
  return {
    contacts,
    expires,
    expiresInDays,
    policy,
    hasSignature: /-----BEGIN PGP SIGNED MESSAGE-----/.test(text),
  };
}

function normalizeWhitespace(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\s+/g, ' ').trim();
}
