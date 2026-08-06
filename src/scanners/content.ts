import { ADULT_KEYWORDS, RTA_LABEL, META_RATING_ADULT } from '../patterns/adult-keywords.js';
import { AFFILIATE_NETWORKS, INTERNAL_REDIRECT_PATTERNS } from '../patterns/affiliate-networks.js';
import { AD_NETWORKS, PUSH_NETWORKS } from '../patterns/ad-networks.js';
import type { ContentClassification, ContentSignal, DetectedAffiliate, DetectedAd } from '../types.js';

/**
 * Keyword regexes are compiled once at module load, not per call. They used to
 * be rebuilt inside the alt-text loop, so a 100-image page cost ~6,600
 * `new RegExp()` constructions per scan.
 *
 * `GLOBAL_*` carry the `g` flag for counting occurrences; `SINGLE_*` are for
 * one-shot tests. They must stay separate — a `g` regex carries `lastIndex`
 * state across `.test()` calls and would skip matches.
 */
const GLOBAL_KEYWORD_RES = ADULT_KEYWORDS.map((kw) => new RegExp(kw.pattern.source, 'gi'));
const SINGLE_KEYWORD_RES = ADULT_KEYWORDS.map((kw) => new RegExp(kw.pattern.source, 'i'));

/**
 * Repeated hits mean more than a single passing mention, but with diminishing
 * returns — one "xxx" in a footer disclaimer should not score the same as a
 * page saturated with it, and 500 hits should not outweigh everything else.
 */
function repetitionWeight(count: number): number {
  if (count >= 10) return 2;
  if (count >= 3) return 1.5;
  return 1;
}

export function scanContent(html: string, domain: string, adultScoreThreshold = 30): ContentClassification {
  const signals: ContentSignal[] = [];
  const affiliateLinks: DetectedAffiliate[] = [];
  const adNetworks: DetectedAd[] = [];

  // Strip HTML tags for keyword scanning (keep text + alt attributes)
  const text = htmlToText(html);
  const altTexts = extractAlts(html);

  // ── Keyword scanning ──
  for (let i = 0; i < ADULT_KEYWORDS.length; i++) {
    const kw = ADULT_KEYWORDS[i];
    const matches = text.match(GLOBAL_KEYWORD_RES[i]);
    if (matches && matches.length > 0) {
      signals.push({
        type: 'keyword',
        value: `${matches[0]} (×${matches.length})`,
        severity: kw.severity,
        location: `body text [${kw.category}]`,
        weight: repetitionWeight(matches.length),
      });
    }
  }

  // ── Domain-name keywords ──
  // The domain itself is content: a clean landing page on an obviously adult
  // hostname should not classify as clean.
  for (let i = 0; i < ADULT_KEYWORDS.length; i++) {
    const kw = ADULT_KEYWORDS[i];
    if (kw.severity === 'low') continue; // too noisy against a short hostname
    const hostname = domain.replace(/[.-]/g, ' ');
    if (SINGLE_KEYWORD_RES[i].test(hostname)) {
      signals.push({
        type: 'domain_name',
        value: domain,
        severity: kw.severity,
        location: `domain name [${kw.category}]`,
      });
      break; // one domain-name signal is enough; don't stack them
    }
  }

  // Check alt texts separately
  for (const alt of altTexts) {
    for (let i = 0; i < ADULT_KEYWORDS.length; i++) {
      const kw = ADULT_KEYWORDS[i];
      if (kw.severity === 'low') continue; // skip low-severity for alt text
      if (SINGLE_KEYWORD_RES[i].test(alt)) {
        signals.push({
          type: 'image_alt',
          value: alt.slice(0, 60),
          severity: kw.severity,
          location: 'img alt attribute',
        });
        break;
      }
    }
  }

  // ── Meta rating / RTA label ──
  const metaRating = html.match(/<meta[^>]+name=['"]rating['"][^>]+content=['"]([^'"]+)['"]/i)?.[1];
  if (metaRating && META_RATING_ADULT.test(metaRating)) {
    signals.push({
      type: 'meta_rating',
      value: metaRating,
      severity: 'critical',
      location: '<meta name="rating">',
    });
  }

  if (RTA_LABEL.test(html)) {
    signals.push({
      type: 'rta_label',
      value: 'RTA-5042-1996-1400-1577-RTA',
      severity: 'critical',
      location: 'HTML source',
    });
  }

  // ── Affiliate link detection ──
  const links = extractLinks(html);
  for (const link of links) {
    const anchor = link.anchor;
    for (const net of AFFILIATE_NETWORKS) {
      if (net.patterns.some((p) => p.test(link.href))) {
        affiliateLinks.push({
          url: link.href,
          network: net.name,
          isAdult: net.isAdult,
          anchorText: anchor,
        });
        if (net.isAdult) {
          signals.push({
            type: 'affiliate',
            value: `${net.name}: ${link.href.slice(0, 80)}`,
            severity: 'critical',
            location: 'affiliate link',
          });
        }
        break;
      }
    }

    // Check for internal redirect patterns (site's own /go/ links)
    for (const rp of INTERNAL_REDIRECT_PATTERNS) {
      if (rp.test(link.href) && !affiliateLinks.find((a) => a.url === link.href)) {
        affiliateLinks.push({
          url: link.href,
          network: null,
          isAdult: false, // unknown, flagged for review
          anchorText: anchor,
        });
        break;
      }
    }
  }

  // ── Ad network detection ──
  const allNetworks = [...AD_NETWORKS, ...PUSH_NETWORKS];
  const scripts = extractScriptSources(html);
  for (const script of scripts) {
    for (const net of allNetworks) {
      if (net.patterns.some((p) => p.test(script))) {
        adNetworks.push({
          name: net.name,
          scriptSrc: script,
          isAdult: net.isAdult,
        });
        if (net.isAdult) {
          signals.push({
            type: 'ad_network',
            value: `${net.name}: ${script.slice(0, 80)}`,
            severity: 'critical',
            location: 'script src',
          });
        }
        break;
      }
    }
  }

  // Also check inline scripts for ad network patterns
  const inlineScripts = extractInlineScripts(html);
  for (const inline of inlineScripts) {
    for (const net of allNetworks) {
      if (net.patterns.some((p) => p.test(inline))) {
        if (!adNetworks.find((a) => a.name === net.name)) {
          adNetworks.push({
            name: net.name,
            scriptSrc: '(inline)',
            isAdult: net.isAdult,
          });
          if (net.isAdult) {
            signals.push({
              type: 'ad_network',
              value: `${net.name} (inline script)`,
              severity: 'critical',
              location: 'inline script',
            });
          }
        }
      }
    }
  }

  // ── Score calculation ──
  const adultScore = calculateAdultScore(signals);

  return {
    isAdult: adultScore >= adultScoreThreshold,
    adultScore,
    signals,
    affiliateLinks,
    adNetworks,
    contentRating: metaRating ?? null,
  };
}

function calculateAdultScore(signals: ContentSignal[]): number {
  let score = 0;
  const weights = { critical: 25, high: 15, medium: 5, low: 1 };

  for (const signal of signals) {
    score += weights[signal.severity] * (signal.weight ?? 1);
  }

  return Math.min(100, Math.round(score));
}

function htmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z]+;/gi, ' ')
    .replace(/\s+/g, ' ');
}

function extractAlts(html: string): string[] {
  const alts: string[] = [];
  const re = /alt=['"]([^'"]+)['"]/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    if (match[1]) alts.push(match[1]);
  }
  return alts;
}

interface LinkInfo {
  href: string;
  anchor: string | null;
}

function extractLinks(html: string): LinkInfo[] {
  const links: LinkInfo[] = [];
  const re = /<a[^>]+href=['"]([^'"]+)['"][^>]*>([\s\S]*?)<\/a>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    links.push({
      href: match[1] ?? '',
      anchor: match[2]?.replace(/<[^>]+>/g, '').trim() ?? null,
    });
  }
  return links;
}

function extractScriptSources(html: string): string[] {
  const sources: string[] = [];
  const re = /<script[^>]+src=['"]([^'"]+)['"]/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    if (match[1]) sources.push(match[1]);
  }
  return sources;
}

function extractInlineScripts(html: string): string[] {
  const scripts: string[] = [];
  const re = /<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    if (match[1]?.trim()) scripts.push(match[1]);
  }
  return scripts;
}
