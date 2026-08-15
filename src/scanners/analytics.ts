import { ANALYTICS_EXTRACTORS, DNS_VERIFICATION_PATTERNS } from '../patterns/analytics-ids.js';
import type { AnalyticsResult, DnsResult } from '../types.js';

export function scanAnalytics(html: string, dnsResult?: DnsResult | null): AnalyticsResult {
  const result: AnalyticsResult = {
    ga4: [],
    gtm: [],
    adsense: [],
    umami: [],
    facebook: [],
    clarity: [],
    plausible: [],
    cloudflare: [],
    other: [],
  };

  for (const extractor of ANALYTICS_EXTRACTORS) {
    for (const pattern of extractor.patterns) {
      const re = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = re.exec(html)) !== null) {
        const id = match[1];
        if (!id) continue;

        switch (extractor.name) {
          case 'GA4 Measurement ID':
            if (!result.ga4.includes(`G-${id}`)) result.ga4.push(`G-${id}`);
            break;
          case 'GTM Container': {
            const gtm = id.startsWith('GTM-') ? id : `GTM-${id}`;
            if (!result.gtm.includes(gtm)) result.gtm.push(gtm);
            break;
          }
          case 'Google AdSense Publisher':
            if (!result.adsense.includes(`ca-pub-${id}`)) result.adsense.push(`ca-pub-${id}`);
            break;
          case 'Umami Website ID':
            if (!result.umami.find((u) => u.websiteId === id)) {
              result.umami.push({ websiteId: id, src: '' });
            }
            break;
          case 'Umami Script Source':
            // Defer pairing — handled after all extractors run
            break;
          case 'Facebook Pixel':
            if (!result.facebook.includes(id)) result.facebook.push(id);
            break;
          case 'Microsoft Clarity':
            if (!result.clarity.includes(id)) result.clarity.push(id);
            break;
          case 'Plausible Domain':
            if (!result.plausible.includes(id)) result.plausible.push(id);
            break;
          case 'Cloudflare Web Analytics':
            // Only keep 32-char hex tokens, not the universal beacon.min.js URL
            if (/^[a-f0-9]{32}$/.test(id) && !result.cloudflare.includes(id)) {
              result.cloudflare.push(id);
            }
            break;
          default:
            if (!result.other.find((o) => o.name === extractor.name && o.id === id)) {
              result.other.push({ name: extractor.name, id });
            }
        }
      }
    }
  }

  // Pair Umami script sources with website IDs by proximity in HTML
  // Each script tag typically contains both data-website-id and src, so we match
  // each src to the closest websiteId by position in the HTML string
  if (result.umami.length > 0) {
    const srcPattern = /src=['"]([^'"]*umami[^'"]*\.js)['"]/g;
    let srcMatch: RegExpExecArray | null;
    const srcPositions: Array<{ src: string; pos: number }> = [];
    while ((srcMatch = srcPattern.exec(html)) !== null) {
      if (srcMatch[1]) srcPositions.push({ src: srcMatch[1], pos: srcMatch.index });
    }
    const idPattern = /data-website-id=['"]([0-9a-f-]{36})['"]/g;
    let idMatch: RegExpExecArray | null;
    const idPositions: Array<{ id: string; pos: number }> = [];
    while ((idMatch = idPattern.exec(html)) !== null) {
      if (idMatch[1]) idPositions.push({ id: idMatch[1], pos: idMatch.index });
    }
    // For each src, find the closest websiteId and pair them
    for (const sp of srcPositions) {
      let closest: { id: string; dist: number } | null = null;
      for (const ip of idPositions) {
        const dist = Math.abs(sp.pos - ip.pos);
        if (!closest || dist < closest.dist) {
          closest = { id: ip.id, dist };
        }
      }
      if (closest) {
        const entry = result.umami.find((u) => u.websiteId === closest!.id);
        if (entry && !entry.src) {
          entry.src = sp.src;
        }
      }
    }
  }

  // Also check DNS TXT records for verification IDs
  if (dnsResult?.txt) {
    for (const txt of dnsResult.txt) {
      for (const vp of DNS_VERIFICATION_PATTERNS) {
        const match = txt.match(vp.pattern);
        if (match?.[1]) {
          result.other.push({ name: `DNS:${vp.name}`, id: match[1] });
        }
      }
    }
  }

  return result;
}

/**
 * Merge tracking IDs found on subpages (sitemap crawl / --pages routes) into the
 * homepage result. Checkout, contact and booking pages are where Stripe keys,
 * reCAPTCHA site keys and form-vendor IDs live — a homepage-only scan misses them.
 */
export function mergeAnalytics(target: AnalyticsResult, source: AnalyticsResult): void {
  const addAll = (dst: string[], src: string[]) => { for (const v of src) if (!dst.includes(v)) dst.push(v); };
  addAll(target.ga4, source.ga4);
  addAll(target.gtm, source.gtm);
  addAll(target.adsense, source.adsense);
  addAll(target.facebook, source.facebook);
  addAll(target.clarity, source.clarity);
  addAll(target.plausible, source.plausible);
  addAll(target.cloudflare, source.cloudflare);
  for (const u of source.umami) {
    if (!target.umami.some((t) => t.websiteId === u.websiteId)) target.umami.push({ ...u });
  }
  for (const o of source.other) {
    if (o.name.startsWith('DNS:')) continue; // DNS tokens are per-domain, already on the target
    if (!target.other.some((t) => t.name === o.name && t.id === o.id)) target.other.push({ ...o });
  }
}
