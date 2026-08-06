import { origin, shortHash } from '../utils.js';
import type { RobotsResult, ScanningConfig } from '../types.js';
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

  return result;
}

function normalizeWhitespace(text: string): string {
  return text.replace(/\r\n/g, '\n').replace(/\s+/g, ' ').trim();
}
