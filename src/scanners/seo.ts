import type { SeoResult, SeoCheck, HtmlResult, RobotsResult } from '../types.js';

interface SeoInput {
  html: HtmlResult | null;
  robots: RobotsResult | null;
  hasHreflang?: boolean;
  /** Hreflang langs found on the site's root page, when scoring a non-root
   *  page (e.g. via `--pages`) — distinguishes "this page has none" (fine if
   *  deliberately untranslated) from "site isn't i18n at all". */
  siteHreflang?: string[];
  statusCode?: number;
  /**
   * Whether the html scanner actually ran. When false, HTML-derived checks are
   * not evaluated (omitted from both the score and the check list) rather than
   * counted as failures — "not scanned" must never read as "absent".
   */
  htmlScanned?: boolean;
  /** Whether the robots scanner actually ran (gates robots.txt + sitemap checks). */
  robotsScanned?: boolean;
  /** Scheme of the final observed response ('http' when the site was actually
   *  served over plain HTTP — via explicit http:// target or https→http fallback). */
  finalScheme?: 'https' | 'http';
  /** True when the page is noindex (meta robots / X-Robots-Tag). Canonical URL,
   *  Hreflang, and Structured Data don't apply — they're skipped, not scored. */
  noindex?: boolean;
}

export function scanSeo(input: SeoInput): SeoResult {
  const checks: SeoCheck[] = [];
  let points = 0;
  let maxPoints = 0;

  const { html, robots } = input;
  const htmlScanned = input.htmlScanned ?? true;
  const robotsScanned = input.robotsScanned ?? true;
  const noindex = input.noindex ?? false;

  // ── HTML-derived checks — only evaluated when the html scanner ran ──
  if (htmlScanned) {
    // ── Title ──
    const titleWeight = 15;
    maxPoints += titleWeight;
    if (!html?.title) {
      checks.push({ name: 'Title', present: false, value: null, rating: 'missing', detail: 'No <title> tag — critical for search rankings' });
    } else {
      const len = html.title.length;
      if (len >= 30 && len <= 60) {
        points += titleWeight;
        checks.push({ name: 'Title', present: true, value: `${len} chars`, rating: 'good', detail: `"${html.title.slice(0, 60)}" (${len} chars — optimal)` });
      } else if ((len >= 25 && len < 30) || (len > 60 && len <= 65)) {
        // Within ±5 of optimal — SERPs render this fine, not worth a warning.
        points += titleWeight;
        checks.push({ name: 'Title', present: true, value: `${len} chars`, rating: 'good', detail: `"${html.title.slice(0, 60)}" (${len} chars — borderline, aim for 30-60)` });
      } else if (len < 25) {
        points += Math.floor(titleWeight / 2);
        checks.push({ name: 'Title', present: true, value: `${len} chars`, rating: 'warning', detail: `"${html.title}" (${len} chars — too short, aim for 30-60)` });
      } else {
        points += Math.floor(titleWeight / 2);
        checks.push({ name: 'Title', present: true, value: `${len} chars`, rating: 'warning', detail: `"${html.title.slice(0, 57)}..." (${len} chars — may truncate in SERPs, aim for 30-60)` });
      }
    }

    // ── Meta Description ──
    const descWeight = 15;
    maxPoints += descWeight;
    if (!html?.metaDescription) {
      checks.push({ name: 'Meta Description', present: false, value: null, rating: 'missing', detail: 'No meta description — Google may generate its own snippet' });
    } else {
      const len = html.metaDescription.length;
      if (len >= 120 && len <= 160) {
        points += descWeight;
        checks.push({ name: 'Meta Description', present: true, value: `${len} chars`, rating: 'good', detail: `${len} chars — optimal length` });
      } else if ((len >= 115 && len < 120) || (len > 160 && len <= 165)) {
        points += descWeight;
        checks.push({ name: 'Meta Description', present: true, value: `${len} chars`, rating: 'good', detail: `${len} chars — borderline, aim for 120-160` });
      } else if (len < 115) {
        points += Math.floor(descWeight / 2);
        checks.push({ name: 'Meta Description', present: true, value: `${len} chars`, rating: 'warning', detail: `${len} chars — short, aim for 120-160` });
      } else {
        points += Math.floor(descWeight / 2);
        checks.push({ name: 'Meta Description', present: true, value: `${len} chars`, rating: 'warning', detail: `${len} chars — may truncate in SERPs, aim for 120-160` });
      }
    }

    // ── Canonical URL ── (skipped on noindex pages — doesn't apply)
    if (!noindex) {
      const canonicalWeight = 10;
      maxPoints += canonicalWeight;
      if (html?.canonicalUrl) {
        points += canonicalWeight;
        checks.push({ name: 'Canonical URL', present: true, value: html.canonicalUrl, rating: 'good', detail: html.canonicalUrl });
      } else {
        checks.push({ name: 'Canonical URL', present: false, value: null, rating: 'missing', detail: 'No canonical URL — risk of duplicate content issues' });
      }
    }

    // ── Open Graph ──
    const ogWeight = 10;
    maxPoints += ogWeight;
    if (html) {
      const og = html.ogTags;
      const required = ['og:title', 'og:description', 'og:image', 'og:type'];
      const present = required.filter((k) => og[k]);
      const missing = required.filter((k) => !og[k]);
      if (missing.length === 0) {
        points += ogWeight;
        checks.push({ name: 'Open Graph', present: true, value: `${present.length}/${required.length}`, rating: 'good', detail: 'All required OG tags present (title, description, image, type)' });
      } else if (present.length > 0) {
        points += Math.floor(ogWeight / 2);
        checks.push({ name: 'Open Graph', present: true, value: `${present.length}/${required.length}`, rating: 'warning', detail: `Missing: ${missing.join(', ')}` });
      } else {
        checks.push({ name: 'Open Graph', present: false, value: null, rating: 'missing', detail: 'No OG tags — social media shares will lack rich previews' });
      }
    }

    // ── Twitter Cards ──
    const twWeight = 5;
    maxPoints += twWeight;
    // `twitterCards` is always an object — `{}` was truthy and every page with
    // zero twitter:* tags scored as "partially configured".
    if (html?.twitterCards && Object.keys(html.twitterCards).length > 0) {
      const tw = html.twitterCards;
      const hasCard = tw['twitter:card'];
      const hasTitle = tw['twitter:title'];
      if (hasCard && hasTitle) {
        points += twWeight;
        checks.push({ name: 'Twitter Card', present: true, value: tw['twitter:card'], rating: 'good', detail: `${tw['twitter:card']} — title and image set` });
      } else {
        points += Math.floor(twWeight / 2);
        checks.push({ name: 'Twitter Card', present: true, value: 'partial', rating: 'warning', detail: 'Twitter card partially configured' });
      }
    } else {
      checks.push({ name: 'Twitter Card', present: false, value: null, rating: 'missing', detail: 'No Twitter card tags' });
    }

    // ── Language ──
    const langWeight = 5;
    maxPoints += langWeight;
    if (html?.htmlLang) {
      points += langWeight;
      checks.push({ name: 'Language', present: true, value: html.htmlLang, rating: 'good', detail: `lang="${html.htmlLang}"` });
    } else {
      checks.push({ name: 'Language', present: false, value: null, rating: 'missing', detail: 'No lang attribute on <html> — hurts accessibility and i18n SEO' });
    }

    // ── Viewport ──
    const vpWeight = 5;
    maxPoints += vpWeight;
    if (html?.metaViewport) {
      points += vpWeight;
      checks.push({ name: 'Viewport', present: true, value: html.metaViewport, rating: 'good', detail: 'Mobile viewport configured' });
    } else {
      checks.push({ name: 'Viewport', present: false, value: null, rating: 'missing', detail: 'No viewport meta — not mobile-friendly (hurts mobile rankings)' });
    }

    // ── JSON-LD Structured Data ── (skipped on noindex pages — doesn't apply)
    if (!noindex) {
      const ldWeight = 10;
      maxPoints += ldWeight;
      if (html?.jsonLd?.length) {
        points += ldWeight;
        const types = html.jsonLd.map((j) => j.type).filter(Boolean);
        checks.push({ name: 'Structured Data', present: true, value: `${html.jsonLd.length} item(s)`, rating: 'good', detail: `JSON-LD: ${types.join(', ') || 'present'}` });
      } else {
        checks.push({ name: 'Structured Data', present: false, value: null, rating: 'missing', detail: 'No JSON-LD structured data — limits rich snippet eligibility' });
      }
    }

    // ── Hreflang ── (derived from the HTML <head>, so gated with the HTML checks;
    // skipped on noindex pages — doesn't apply)
    if (!noindex) {
      const hreflangWeight = 5;
      maxPoints += hreflangWeight;
      if (input.hasHreflang) {
        points += hreflangWeight;
        checks.push({ name: 'Hreflang', present: true, value: 'present', rating: 'good', detail: 'hreflang alternate links configured for i18n' });
      } else if (input.siteHreflang?.length) {
        // The site is known i18n (root has hreflang) but this specific page
        // doesn't — could be a deliberately untranslated page, not a bug.
        checks.push({ name: 'Hreflang', present: false, value: null, rating: 'warning', detail: `site is i18n (root: ${input.siteHreflang.join(', ')}) — this page has none: fine if untranslated, else add self-ref + x-default` });
      } else {
        // Not missing per se — only matters for multilingual sites
        checks.push({ name: 'Hreflang', present: false, value: null, rating: 'warning', detail: 'No hreflang — add if site has multiple language versions' });
      }
    }
  }

  // ── robots.txt + sitemap — only evaluated when the robots scanner ran ──
  if (robotsScanned) {
    // ── Robots.txt ──
    const robotsWeight = 5;
    maxPoints += robotsWeight;
    if (robots?.robotsTxt) {
      points += robotsWeight;
      checks.push({ name: 'robots.txt', present: true, value: 'present', rating: 'good', detail: 'robots.txt found' });
    } else {
      checks.push({ name: 'robots.txt', present: false, value: null, rating: 'missing', detail: 'No robots.txt — crawlers have no directives' });
    }

    // ── Sitemap ──
    const sitemapWeight = 10;
    maxPoints += sitemapWeight;
    if (robots?.sitemapUrls?.length) {
      points += sitemapWeight;
      checks.push({ name: 'Sitemap', present: true, value: `${robots.sitemapUrls.length} URL(s)`, rating: 'good', detail: `Sitemap: ${robots.sitemapUrls[0]}` });
    } else {
      checks.push({ name: 'Sitemap', present: false, value: null, rating: 'missing', detail: 'No sitemap referenced in robots.txt — slower crawl discovery' });
    }
  }

  // ── HTTPS ── (self-gating: only scored when a status code was actually observed)
  const httpsWeight = 5;
  if (input.statusCode && input.statusCode >= 200 && input.statusCode < 400) {
    maxPoints += httpsWeight;
    if (input.finalScheme === 'http') {
      // Reached over plain HTTP — never claim "served over HTTPS" (the old check
      // did, purely because a 2xx arrived). No points: fine for LAN/staging,
      // must be HTTPS before production.
      checks.push({ name: 'HTTPS', present: false, value: 'http', rating: 'warning', detail: 'Served over plain HTTP — acceptable for LAN/staging only, must be HTTPS in production' });
    } else {
      points += httpsWeight;
      checks.push({ name: 'HTTPS', present: true, value: 'yes', rating: 'good', detail: 'Site served over HTTPS' });
    }
  } else if (input.statusCode) {
    maxPoints += httpsWeight;
    checks.push({ name: 'HTTPS', present: true, value: `HTTP ${input.statusCode}`, rating: 'warning', detail: `Unexpected status: ${input.statusCode}` });
  }

  // maxPoints is 0 only when neither source scanner produced a result (e.g. the
  // HTTP fetch both html and robots depend on failed) — that's "not evaluated",
  // not a perfect (nor a zero) score. Don't fabricate either.
  const score = maxPoints === 0 ? null : Math.round((points / maxPoints) * 100);
  const skipped = noindex && htmlScanned ? ['Canonical URL', 'Hreflang', 'Structured Data'] : undefined;
  return { score, checks, evaluated: checks.length, total: SEO_TOTAL_CHECKS, ...(skipped ? { skipped } : {}) };
}

/** Checks a full scan evaluates: 9 HTML-derived + 2 robots-derived + HTTPS. */
export const SEO_TOTAL_CHECKS = 12;
