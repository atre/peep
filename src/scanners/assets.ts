import { shortHash } from '../utils.js';
import { isFetchAllowed, readCapped, readCappedBuffer } from '../fetch-guard.js';
import type { AssetResult, ScanningConfig } from '../types.js';

/** Assets are fetched only to hash them — 5 MB is far past any real favicon/CSS/JS. */
const MAX_ASSET_BYTES = 5 * 1024 * 1024;

/**
 * Fetch a URL that came out of the scanned page's HTML. Returns null when the
 * SSRF guard rejects it, so callers fall back to URL-based hashing.
 */
async function guardedFetch(
  url: string,
  targetHost: string,
  config: ScanningConfig,
): Promise<Response | null> {
  const verdict = await isFetchAllowed(url, targetHost);
  if (!verdict.allowed) return null;
  return fetch(url, {
    signal: AbortSignal.timeout(config.timeout),
    headers: { 'User-Agent': config.userAgent },
  });
}

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
  // faviconUrl is only recorded when the file actually exists — the implicit
  // /favicon.ico fallback used to be reported as the favicon even on a 404.
  const declaredFavicon = extractFaviconUrl(html);
  const faviconUrl = resolveUrl(domain, declaredFavicon ?? '/favicon.ico', config.scheme);
  try {
    const resp = await guardedFetch(faviconUrl, domain, config);
    if (resp?.ok) {
      const buf = await readCappedBuffer(resp, MAX_ASSET_BYTES);
      result.faviconUrl = faviconUrl;
      result.faviconHash = shortHash(buf.toString('base64'));
    } else if (declaredFavicon) {
      result.faviconUrl = faviconUrl; // declared but broken — worth showing
    }
  } catch {
    if (declaredFavicon) result.faviconUrl = faviconUrl;
  }

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
  // Blocks non-HTTP schemes (javascript:, data:, file:, …). Private-address
  // filtering is NOT done here — it needs DNS resolution, so it lives in the
  // async guard in fetch-guard.ts that every fetch below goes through.
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
      const resp = await guardedFetch(url, domain, config);
      if (resp?.ok) {
        const text = await readCapped(resp, MAX_ASSET_BYTES);
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
      const resp = await guardedFetch(url, domain, config);
      return { url: href, content: resp?.ok ? await readCapped(resp, MAX_ASSET_BYTES) : '' };
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
      if (name && isRealFontFamily(name)) out.add(name);
    }
  }
  return [...out];
}

/**
 * Generic/system families and CSS keywords that every stack declares as
 * fallbacks. They carry zero fingerprint value and, together with `var(...)`
 * references, turned the Fonts line into ~600 chars of noise on a Tailwind v4
 * / Next.js site.
 */
const GENERIC_FONT_TOKENS = new Set([
  'serif', 'sans-serif', 'monospace', 'cursive', 'fantasy', 'system-ui', 'ui-serif',
  'ui-sans-serif', 'ui-monospace', 'ui-rounded', 'emoji', 'math', 'fangsong',
  '-apple-system', 'blinkmacsystemfont', 'segoe ui', 'segoe ui emoji', 'segoe ui symbol',
  'apple color emoji', 'noto color emoji', 'roboto', 'helvetica', 'helvetica neue', 'arial',
  'liberation mono', 'liberation sans', 'menlo', 'monaco', 'consolas', 'courier new', 'courier',
  'sfmono-regular', 'sf mono', 'sf pro', 'sf pro text', 'sf pro display', 'times new roman',
  'times', 'georgia', 'verdana', 'tahoma', 'inherit', 'initial', 'unset', 'revert', 'revert-layer',
  'noto sans', 'ubuntu', 'cantarell', 'fira sans', 'droid sans', 'oxygen', 'oxygen-sans',
]);

/** True for a token that names an actual, fingerprint-worthy font family. */
export function isRealFontFamily(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower.startsWith('var(') || lower.startsWith('env(') || lower.startsWith('--')) return false;
  if (GENERIC_FONT_TOKENS.has(lower)) return false;
  // Values that leaked from a broken parse (contain CSS punctuation)
  if (/[:;{}]/.test(name)) return false;
  return true;
}
