import { shortHash } from '../utils.js';
import type { AssetResult, ScanningConfig } from '../types.js';

export async function scanAssets(domain: string, html: string, config: ScanningConfig): Promise<AssetResult> {
  const result: AssetResult = {
    faviconHash: null,
    faviconUrl: null,
    cssHashes: [],
    jsHashes: [],
    fontFamilies: [],
    fontSources: [],
    imageCount: 0,
    ogImages: [],
  };

  // Favicon
  const faviconHref = extractFaviconUrl(html) ?? '/favicon.ico';
  const faviconUrl = resolveUrl(domain, faviconHref, config.scheme);
  result.faviconUrl = faviconUrl;
  try {
    const resp = await fetch(faviconUrl, {
      signal: AbortSignal.timeout(config.timeout),
      headers: { 'User-Agent': config.userAgent },
    });
    if (resp.ok) {
      const buf = Buffer.from(await resp.arrayBuffer());
      result.faviconHash = shortHash(buf.toString('base64'));
    }
  } catch {}

  // External CSS files — always fetch content for font extraction; hash content or URL per config
  const cssUrls = extractAll(html, /<link[^>]+href=['"]([^'"]+\.css[^'"]*)['"]/gi);
  const cssContents = await fetchCssContents(cssUrls, domain, config);
  const allCssContent = cssContents.map((c) => c.content).join('\n');
  result.cssHashes = cssContents.map((c) => ({
    url: c.url,
    hash: config.hashContent && c.content ? shortHash(c.content) : shortHash(c.url),
  }));

  // External JS files
  const jsUrls = extractAll(html, /<script[^>]+src=['"]([^'"]+\.js[^'"]*)['"]/gi);
  if (config.hashContent) {
    result.jsHashes = await hashFileContents(jsUrls, domain, config);
  } else {
    result.jsHashes = jsUrls.map((url) => ({ url, hash: shortHash(url) }));
  }

  // Font families + sources: check both HTML and fetched CSS content
  const combinedText = html + '\n' + allCssContent;

  // Font families: parse external CSS, <style> blocks, and inline style="" attrs.
  // Normalizing all three to "css-like" text lets one declaration parser (value
  // terminates at ; } {) handle them without an attribute quote truncating a value
  // mid-stack — the Tailwind v4 var() garbling bug. cleanFontFamilies then does a
  // paren-aware comma split, strips quotes, drops empty tokens (doubled commas),
  // and dedupes to real family names.
  const styleBlocks = extractAll(html, /<style[^>]*>([\s\S]*?)<\/style>/gi);
  const inlineStyles = [
    ...extractAll(html, /style\s*=\s*"([^"]*)"/gi),
    ...extractAll(html, /style\s*=\s*'([^']*)'/gi),
  ];
  const cssLike = [allCssContent, ...styleBlocks, ...inlineStyles].join('\n');
  const fontDecls = cssLike.match(/font-family\s*:\s*([^;}{]+)/gi) ?? [];
  result.fontFamilies = cleanFontFamilies(fontDecls.map((m) => m.replace(/font-family\s*:\s*/i, '')));

  // Font file sources from HTML and CSS @font-face url() declarations
  const fontSrcMatches = extractAll(combinedText, /url\(['"]?([^'")\s]+\.(?:woff2?|ttf|otf|eot)[^'")\s]*)/gi);
  result.fontSources = [...new Set(fontSrcMatches)];

  // Image count (including inline SVGs)
  const imgTags = html.match(/<img\b/gi) ?? [];
  const svgTags = html.match(/<svg\b/gi) ?? [];
  const bgImages = html.match(/background(?:-image)?\s*:[^;>"'{}]*url\(/gi) ?? [];
  result.imageCount = imgTags.length + svgTags.length + bgImages.length;

  // OG / Twitter card images (meta tag images not counted in imageCount)
  const ogImageSet = new Set<string>();
  const ogImgRe = /<meta[^>]+(?:property=['"]og:image['"]|name=['"]twitter:image['"])[^>]+content=['"]([^'"]+)['"]/gi;
  let ogMatch: RegExpExecArray | null;
  while ((ogMatch = ogImgRe.exec(html)) !== null) {
    if (ogMatch[1]) ogImageSet.add(ogMatch[1]);
  }
  // Also handle reversed attribute order
  const ogImgRe2 = /<meta[^>]+content=['"]([^'"]+)['"]+[^>]+(?:property=['"]og:image['"]|name=['"]twitter:image['"])/gi;
  while ((ogMatch = ogImgRe2.exec(html)) !== null) {
    if (ogMatch[1]) ogImageSet.add(ogMatch[1]);
  }
  result.ogImages = [...ogImageSet];

  return result;
}

function extractFaviconUrl(html: string): string | null {
  const match = html.match(/<link[^>]+rel=['"](?:shortcut )?icon['"][^>]+href=['"]([^'"]+)['"]/i);
  return match?.[1] ?? null;
}

function resolveUrl(domain: string, href: string, scheme?: 'https' | 'http'): string {
  const base = scheme ?? 'https';
  let url: string;
  if (href.startsWith('http://') || href.startsWith('https://')) url = href;
  else if (href.startsWith('//')) url = `${base}:${href}`;
  else url = `${base}://${domain}${href.startsWith('/') ? '' : '/'}${href}`;
  // Block non-HTTP schemes (javascript:, data:, file:, etc.) and private IPs
  if (!/^https?:\/\//i.test(url)) return `${base}://${domain}/invalid`;
  return url;
}

async function hashFileContents(
  urls: string[],
  domain: string,
  config: ScanningConfig,
): Promise<Array<{ url: string; hash: string }>> {
  return Promise.all(urls.map(async (href) => {
    const url = resolveUrl(domain, href, config.scheme);
    try {
      const resp = await fetch(url, {
        signal: AbortSignal.timeout(config.timeout),
        headers: { 'User-Agent': config.userAgent },
      });
      if (resp.ok) {
        const text = await resp.text();
        return { url: href, hash: shortHash(text) };
      }
      return { url: href, hash: shortHash(href) };
    } catch {
      return { url: href, hash: shortHash(href) };
    }
  }));
}

async function fetchCssContents(
  cssUrls: string[],
  domain: string,
  config: ScanningConfig,
): Promise<Array<{ url: string; content: string }>> {
  if (cssUrls.length === 0) return [];
  return Promise.all(cssUrls.map(async (href) => {
    const url = resolveUrl(domain, href, config.scheme);
    try {
      const resp = await fetch(url, {
        signal: AbortSignal.timeout(config.timeout),
        headers: { 'User-Agent': config.userAgent },
      });
      return { url: href, content: resp.ok ? await resp.text() : '' };
    } catch {
      return { url: href, content: '' };
    }
  }));
}

function extractAll(html: string, pattern: RegExp): string[] {
  const results: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(html)) !== null) {
    if (match[1]) results.push(match[1]);
  }
  return results;
}

/**
 * Split a comma-separated CSS value on top-level commas only, so commas inside
 * `var(--x, fallback)` or `"Quoted, Name"` stay attached to their token. Without
 * this, a Tailwind v4 stack like `var(--font-sans), var(--font-mono)` would be
 * shredded mid-`var()`.
 */
export function splitTopLevelCommas(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let buf = '';
  for (const ch of value) {
    if (quote) {
      if (ch === quote) quote = null;
      buf += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      buf += ch;
    } else if (ch === '(') {
      depth++;
      buf += ch;
    } else if (ch === ')') {
      if (depth > 0) depth--;
      buf += ch;
    } else if (ch === ',' && depth === 0) {
      out.push(buf);
      buf = '';
    } else {
      buf += ch;
    }
  }
  if (buf) out.push(buf);
  return out;
}

/**
 * Normalize raw font-family declaration values into clean, deduped family tokens.
 * Strips wrapping quotes, collapses whitespace, drops empty tokens (the doubled
 * commas Tailwind v4 emits), and keeps `var(...)` references intact as single
 * tokens rather than truncating them.
 */
export function cleanFontFamilies(rawValues: string[]): string[] {
  const out = new Set<string>();
  for (const raw of rawValues) {
    for (const token of splitTopLevelCommas(raw)) {
      const name = token
        .trim()
        .replace(/^['"]+|['"]+$/g, '')
        .replace(/\s+/g, ' ')
        .trim();
      if (name) out.add(name);
    }
  }
  return [...out];
}
