import { readCapped } from '../fetch-guard.js';
import { scanDns } from './dns.js';
import { scanHttp, buildRequestHeaders } from './http.js';
import { scanTls } from './tls.js';
import { scanWhois } from './whois.js';
import { scanHtml } from './html.js';
import { scanAnalytics, mergeAnalytics } from './analytics.js';
import { scanAssets } from './assets.js';
import { scanRobots } from './robots.js';
import { scanContent } from './content.js';
import { scanSecurity, annotateHostDefaults } from './security.js';
import { scanSeo } from './seo.js';
import { scanTech } from './tech.js';
import type { ScanResult, ScanningConfig, RobotsResult, PageAudit, HreflangAlternate, AnalyticsResult } from '../types.js';
import { collectExposedIdentifiers, EXPLICIT_HTTP_TARGET_SKIP_REASON } from '../utils.js';
import { toFindings } from '../findings.js';

export interface ScanOptions {
  config: ScanningConfig;
  adultScoreThreshold?: number;
  skipWhois?: boolean;
  skipAssets?: boolean;
  only?: string[];
  /** Fetch top N pages from sitemap and merge form endpoints + analytics */
  pages?: number;
  /** Explicit routes (e.g. ["/de", "/fr"]) to audit for SEO/hreflang per page. */
  pageRoutes?: string[];
}

export const KNOWN_SCANNERS = ['dns', 'http', 'tls', 'whois', 'html', 'analytics', 'assets', 'robots', 'content', 'security', 'tech'] as const;

/**
 * Derived scanners are addressable via --only but own no scanner of their own —
 * they are scores computed over other scanners' output. Selecting one runs its
 * source scanners and then the derivation. `security` is NOT here: it is a
 * first-class scanner already in KNOWN_SCANNERS.
 */
export const DERIVED_SCANNERS: Record<string, readonly string[]> = {
  seo: ['html', 'robots', 'http'],
};

/** Every name that --only accepts: real scanners plus derived scores. */
export const SELECTABLE_SCANNERS: string[] = [...KNOWN_SCANNERS, ...Object.keys(DERIVED_SCANNERS)];

function containsNoindex(value: string | null | undefined): boolean {
  if (!value) return false;
  return /noindex/i.test(value);
}

export function validateScannerNames(names: string[]): string[] {
  const known = new Set<string>(SELECTABLE_SCANNERS);
  return names.filter((n) => !known.has(n));
}

/**
 * Expand derived scanner names (e.g. 'seo') into the underlying source scanners
 * that must run, preserving the original selections. Unknown names pass through
 * unchanged (validateScannerNames surfaces those separately).
 */
export function expandScanners(only: string[]): string[] {
  const out = new Set<string>();
  for (const name of only) {
    out.add(name);
    const deps = DERIVED_SCANNERS[name];
    if (deps) for (const d of deps) out.add(d);
  }
  return [...out];
}

export async function scanDomain(domain: string, opts: ScanOptions): Promise<ScanResult> {
  const start = Date.now();
  const result: ScanResult = {
    domain,
    url: `${opts.config.scheme ?? 'https'}://${domain}`,
    timestamp: new Date().toISOString(),
    duration: 0,
    isNoindex: false,
    dns: null,
    http: null,
    tls: null,
    whois: null,
    html: null,
    analytics: null,
    assets: null,
    robots: null,
    content: null,
    security: null,
    seo: null,
    tech: null,
    errors: [],
  };

  // Expand derived selections (e.g. --only seo → html, robots, http) before gating.
  const selected = opts.only ? expandScanners(opts.only) : null;
  const should = (name: string) => !selected || selected.includes(name);

  // Phase 1: Network scans (parallel) — HTTP now returns the body for reuse
  let htmlBody: string | null = null;
  // HTTP result stored separately so downstream scanners can use headers
  // even when 'http' isn't in --only
  let httpHeaders: Record<string, string> | null = null;
  let xRobotsTag: string | null = null;
  const phase1: Promise<void>[] = [];

  if (should('dns')) {
    phase1.push(
      scanDns(domain, opts.config.dnsServer)
        .then((r) => { result.dns = r; })
        .catch((e) => { result.errors.push({ scanner: 'dns', error: (e as Error).message }); }),
    );
  }

  const needsHttp = should('http') || should('html') || should('analytics') || should('assets') || should('content') || should('security') || should('tech');
  if (needsHttp) {
    phase1.push(
      scanHttp(domain, opts.config)
        .then(({ result: httpResult, body }) => {
          if (should('http')) result.http = httpResult;
          httpHeaders = httpResult.headers;
          xRobotsTag = httpResult.xRobotsTag;
          htmlBody = body;
        })
        .catch((e) => { result.errors.push({ scanner: 'http', error: (e as Error).message }); }),
    );
  }

  // An explicit http:// target (e.g. `localhost:9999`) was never expected to
  // have TLS at all — attempting the connection just produces a raw ENOTFOUND.
  // Skip outright and record why, same convention as WHOIS below.
  const explicitHttpTarget = opts.config.scheme === 'http';
  if (should('tls')) {
    if (explicitHttpTarget) {
      result.errors.push({ scanner: 'tls', error: EXPLICIT_HTTP_TARGET_SKIP_REASON });
    } else {
      phase1.push(
        scanTls(domain, opts.config.timeout, opts.config.hostOverride)
          .then((r) => { result.tls = r; })
          .catch((e) => { result.errors.push({ scanner: 'tls', error: (e as Error).message }); }),
      );
    }
  }

  // An explicit `--only whois` outranks `scanning.whoisEnabled: false` in .peeprc —
  // the config default exists to keep routine fleet scans fast, not to silently
  // swallow a scanner the user just asked for by name. `--skip-whois` still wins,
  // but then says so instead of leaving the section silently absent.
  const whoisExplicit = opts.only?.includes('whois') ?? false;
  if (should('whois') && !opts.skipWhois && (opts.config.whoisEnabled || whoisExplicit)) {
    // Same reasoning as TLS above: `localhost:9999` is not a registrable
    // domain — WHOIS would otherwise fail raw with "Invalid domain for WHOIS".
    if (explicitHttpTarget) {
      result.errors.push({ scanner: 'whois', error: EXPLICIT_HTTP_TARGET_SKIP_REASON });
    } else {
      phase1.push(
        scanWhois(domain)
          .then((r) => { result.whois = r; })
          .catch((e) => { result.errors.push({ scanner: 'whois', error: (e as Error).message }); }),
      );
    }
  }

  if (should('robots')) {
    phase1.push(
      scanRobots(domain, opts.config)
        .then((r) => { result.robots = r; })
        .catch((e) => { result.errors.push({ scanner: 'robots', error: (e as Error).message }); }),
    );
  }

  if (whoisExplicit && opts.skipWhois) {
    result.errors.push({ scanner: 'whois', error: 'skipped — --skip-whois overrides --only whois' });
  }

  await Promise.all(phase1);

  // Phase 2: HTML-dependent scans (reuse body from HTTP scanner)
  if (htmlBody) {
    if (should('html')) {
      try { result.html = scanHtml(htmlBody); }
      catch (e) { result.errors.push({ scanner: 'html', error: (e as Error).message }); }
    }

    if (should('analytics')) {
      try { result.analytics = scanAnalytics(htmlBody, result.dns); }
      catch (e) { result.errors.push({ scanner: 'analytics', error: (e as Error).message }); }
    }

    if (should('assets') && !opts.skipAssets) {
      try { result.assets = await scanAssets(domain, htmlBody, opts.config); }
      catch (e) { result.errors.push({ scanner: 'assets', error: (e as Error).message }); }
    }

    if (should('content')) {
      try { result.content = scanContent(htmlBody, domain, opts.adultScoreThreshold); }
      catch (e) { result.errors.push({ scanner: 'content', error: (e as Error).message }); }
    }
  }

  // Phase 3: Header-based scans (only need HTTP headers, not HTML body)
  if (should('security') && httpHeaders) {
    try {
      result.security = scanSecurity(httpHeaders, {
        hasSecurityTxt: result.robots != null ? result.robots.securityTxt != null : undefined,
        commentCount: result.html?.comments.length ?? 0,
        scriptSources: result.html?.scriptSources ?? [],
        domain,
      });
    }
    catch (e) { result.errors.push({ scanner: 'security', error: (e as Error).message }); }
  }

  // Compute isNoindex from HTML meta robots + X-Robots-Tag header (needed by SEO scoring below)
  result.isNoindex = containsNoindex(result.html?.metaRobots) || containsNoindex(xRobotsTag);

  // SEO scoring (uses html + robots results, no extra network requests)
  if (result.html || result.robots) {
    try {
      const hasHreflang = htmlBody ? /<link[^>]+hreflang\s*=/i.test(htmlBody) : false;
      result.seo = scanSeo({
        html: result.html,
        robots: result.robots,
        hasHreflang,
        statusCode: result.http?.statusCode,
        finalScheme: result.http?.finalUrl?.startsWith('http://') ? 'http' : (result.http?.finalUrl ? 'https' : undefined),
        // Tell the scorer which sources actually produced a result — NOT just
        // whether they were selected via --only. A selected scanner whose
        // upstream fetch failed (result.html/robots still null) must read as
        // "not evaluated", never as a page that was fetched and found empty
        // (that was the false "No <title> tag" / 0-score bug: should('html')
        // stayed true even when the HTTP fetch it depends on had errored).
        htmlScanned: result.html != null,
        robotsScanned: result.robots != null,
        noindex: result.isNoindex,
      });
    }
    catch (e) { result.errors.push({ scanner: 'seo', error: (e as Error).message }); }
  }

  if (should('tech') && httpHeaders) {
    try { result.tech = scanTech(htmlBody ?? '', httpHeaders, result.html, result.dns); }
    catch (e) { result.errors.push({ scanner: 'tech', error: (e as Error).message }); }
  }

  if (result.security && result.tech) {
    annotateHostDefaults(result.security.headers, result.tech.technologies.map((t) => t.name));
  }

  result.exposedIdentifiers = collectExposedIdentifiers(result);
  result.findings = toFindings(result);

  // Multi-page scanning: fetch top N sitemap pages and merge form endpoints
  if (opts.pages && opts.pages > 0 && result.robots?.sitemapUrls.length) {
    try {
      const extra = await scanExtraPages(domain, result.robots.sitemapUrls, opts.pages, opts.config, result.analytics != null);
      const extraEndpoints = extra.formEndpoints;
      if (result.analytics) for (const a of extra.analytics) mergeAnalytics(result.analytics, a);
      if (result.html && extraEndpoints.length > 0) {
        const existing = new Set(result.html.formEndpoints);
        for (const ep of extraEndpoints) {
          if (!existing.has(ep)) {
            result.html.formEndpoints.push(ep);
            existing.add(ep);
          }
        }
      }
    } catch {
      // Multi-page scan failed — non-fatal
    }
  }

  // Per-page audit: explicit routes (e.g. /de) get a full SEO/hreflang pass that a
  // single homepage scan can't reach — the i18n gap. Form endpoints found here are
  // also merged into correlation, same as the sitemap crawl above.
  if (opts.pageRoutes?.length) {
    try {
      const siteHreflang = [...new Set((htmlBody ? extractHreflang(htmlBody) : []).map((h) => h.lang))];
      const { audits, analytics: pageAnalytics } = await auditPages(domain, opts.pageRoutes, result.robots, opts.config, result.analytics != null, siteHreflang);
      result.pageAudits = audits;
      if (result.analytics) for (const a of pageAnalytics) mergeAnalytics(result.analytics, a);
      if (result.html) {
        const existing = new Set(result.html.formEndpoints);
        for (const a of audits) {
          for (const ep of a.formEndpoints) {
            if (!existing.has(ep)) {
              result.html.formEndpoints.push(ep);
              existing.add(ep);
            }
          }
        }
      }
    } catch {
      // Per-page audit failed — non-fatal
    }
  }

  result.duration = Date.now() - start;
  return result;
}

/** Resolve a CLI route ("/de", "de/contact", or a full URL) to an absolute URL. */
export function resolvePageUrl(domain: string, route: string, scheme?: 'https' | 'http'): string {
  const base = scheme ?? 'https';
  if (/^https?:\/\//i.test(route)) return route;
  try {
    return new URL(route, `${base}://${domain}/`).toString();
  } catch {
    return `${base}://${domain}${route.startsWith('/') ? route : `/${route}`}`;
  }
}

/** Extract <link rel="alternate" hreflang="…" href="…"> pairs from page HTML. */
export function extractHreflang(html: string): HreflangAlternate[] {
  const out: HreflangAlternate[] = [];
  const linkRe = /<link\b[^>]*\brel=['"]alternate['"][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) !== null) {
    const tag = m[0];
    const lang = /\bhreflang=['"]([^'"]+)['"]/i.exec(tag)?.[1];
    const href = /\bhref=['"]([^'"]+)['"]/i.exec(tag)?.[1];
    if (lang && href) out.push({ lang, href });
  }
  return out;
}

/** Fetch and audit each explicit route for SEO/hreflang signals. */
async function auditPages(
  domain: string,
  routes: string[],
  robots: RobotsResult | null,
  config: ScanningConfig,
  wantAnalytics = true,
  siteHreflang: string[] = [],
): Promise<{ audits: PageAudit[]; analytics: AnalyticsResult[] }> {
  const analytics: AnalyticsResult[] = [];
  const audits = await Promise.all(routes.map(async (route) => {
    const url = resolvePageUrl(domain, route, config.scheme);
    const audit: PageAudit = {
      route, url, statusCode: null, ok: false, title: null, htmlLang: null,
      canonicalUrl: null, isNoindex: false, hreflang: [], seoScore: null, seoIssues: [], formEndpoints: [],
    };
    try {
      const resp = await fetch(url, {
        signal: AbortSignal.timeout(config.timeout),
        headers: buildRequestHeaders(config),
        redirect: 'follow',
      });
      audit.statusCode = resp.status;
      audit.ok = resp.ok;
      if (!resp.ok) return audit;

      const html = await readCapped(resp);
      const xRobotsTag = resp.headers.get('x-robots-tag');
      const pageHtml = scanHtml(html);
      const isNoindex = containsNoindex(pageHtml.metaRobots) || containsNoindex(xRobotsTag);
      const seo = scanSeo({
        html: pageHtml,
        robots,
        hasHreflang: /<link[^>]+hreflang\s*=/i.test(html),
        siteHreflang,
        statusCode: resp.status,
        finalScheme: (resp.url || url).startsWith('http://') ? 'http' : 'https',
        htmlScanned: true,
        robotsScanned: robots != null,
        noindex: isNoindex,
        route,
      });

      audit.title = pageHtml.title;
      audit.htmlLang = pageHtml.htmlLang;
      audit.canonicalUrl = pageHtml.canonicalUrl;
      audit.isNoindex = isNoindex;
      audit.hreflang = extractHreflang(html);
      audit.seoScore = seo.score;
      audit.seoEvaluated = seo.evaluated;
      audit.seoIssues = seo.checks.filter((ch) => ch.rating !== 'good');
      audit.formEndpoints = pageHtml.formEndpoints;
      if (wantAnalytics) analytics.push(scanAnalytics(html));
    } catch {
      // Individual route fetch failed — return the shell with ok=false.
    }
    return audit;
  }));
  return { audits, analytics };
}

/** Most child sitemaps to follow from a <sitemapindex> before giving up. */
const MAX_CHILD_SITEMAPS = 5;

export interface SitemapParse {
  /** True when this document is a <sitemapindex> whose locs are child sitemaps. */
  isIndex: boolean;
  /** Raw <loc> values in document order (child sitemaps for an index, pages otherwise). */
  locs: string[];
  /** locs filtered to fetchable HTML pages — only meaningful when !isIndex. */
  pageUrls: string[];
}

/** Extract all <loc> values from sitemap/sitemapindex XML. */
export function extractSitemapLocs(xml: string): string[] {
  const locRe = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  const out: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = locRe.exec(xml)) !== null) {
    if (match[1]) out.push(match[1]);
  }
  return out;
}

/** True when a URL points at a fetchable HTML page (not the already-scanned apex,
 *  a nested sitemap, or a binary/asset resource). */
export function isHtmlPageUrl(url: string, domain: string): boolean {
  if (url.endsWith(`${domain}/`) || url.endsWith(`${domain}`)) return false;
  return !/\.(xml|xml\.gz|gz|txt|pdf|jpe?g|png|svg|gif|webp|ico|css|js|json|rss|atom)$/i.test(url);
}

/**
 * Parse a single sitemap document. Detecting <sitemapindex> is the fix for the
 * Astro/standard layout where sitemap-index.xml's children all end in .xml and
 * were previously discarded by the page filter, yielding zero subpages.
 */
export function parseSitemap(xml: string, domain: string): SitemapParse {
  const isIndex = /<sitemapindex[\s>]/i.test(xml);
  const locs = extractSitemapLocs(xml);
  const pageUrls = isIndex ? [] : locs.filter((u) => isHtmlPageUrl(u, domain));
  return { isIndex, locs, pageUrls };
}

async function fetchSitemap(url: string, config: ScanningConfig): Promise<string | null> {
  try {
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(config.timeout),
      headers: { 'User-Agent': config.userAgent },
    });
    if (!resp.ok) return null;
    return await readCapped(resp);
  } catch {
    return null;
  }
}

/** Collect up to maxPages HTML page URLs from a sitemap, following one level of
 *  <sitemapindex> into child sitemaps when needed. */
async function collectSitemapPageUrls(
  sitemapUrl: string,
  domain: string,
  maxPages: number,
  config: ScanningConfig,
): Promise<string[]> {
  const xml = await fetchSitemap(sitemapUrl, config);
  if (!xml) return [];

  const parsed = parseSitemap(xml, domain);
  if (!parsed.isIndex) return parsed.pageUrls.slice(0, maxPages);

  // Sitemap index — recurse one level into child sitemaps (no deeper).
  const pages: string[] = [];
  for (const childUrl of parsed.locs.slice(0, MAX_CHILD_SITEMAPS)) {
    const childXml = await fetchSitemap(childUrl, config);
    if (!childXml) continue;
    for (const pageUrl of parseSitemap(childXml, domain).pageUrls) {
      pages.push(pageUrl);
      if (pages.length >= maxPages) return pages;
    }
  }
  return pages;
}

async function scanExtraPages(
  domain: string,
  sitemapUrls: string[],
  maxPages: number,
  config: ScanningConfig,
  wantAnalytics = true,
): Promise<{ formEndpoints: string[]; analytics: AnalyticsResult[] }> {
  const empty = { formEndpoints: [], analytics: [] };
  const sitemapUrl = sitemapUrls[0];
  if (!sitemapUrl) return empty;

  const pageUrls = await collectSitemapPageUrls(sitemapUrl, domain, maxPages, config);
  if (pageUrls.length === 0) return empty;

  // Fetch pages in parallel and extract form endpoints + tracking IDs
  const allEndpoints: string[] = [];
  const analytics: AnalyticsResult[] = [];
  await Promise.all(pageUrls.map(async (url) => {
    try {
      const resp = await fetch(url, {
        signal: AbortSignal.timeout(config.timeout),
        headers: buildRequestHeaders(config),
      });
      if (!resp.ok) return;
      const html = await readCapped(resp);
      const pageResult = scanHtml(html);
      allEndpoints.push(...pageResult.formEndpoints);
      if (wantAnalytics) analytics.push(scanAnalytics(html));
    } catch {
      // Individual page fetch failed — skip
    }
  }));

  return { formEndpoints: allEndpoints, analytics };
}
