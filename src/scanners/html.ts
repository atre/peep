import { shortHash, escapeRegex } from '../utils.js';
import type { HtmlResult, JsonLdData } from '../types.js';

function decodeHtmlEntities(str: string): string {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)));
}

export function scanHtml(html: string): HtmlResult {
  const metaRobots = extractMetaTag(html, 'robots') ?? extractMetaTag(html, 'googlebot');
  const rawTitle = extractMeta(html, /<title[^>]*>([^<]+)<\/title>/i);
  return {
    title: rawTitle ? decodeHtmlEntities(rawTitle) : null,
    metaGenerator: extractMetaTag(html, 'generator'),
    metaViewport: extractMetaTag(html, 'viewport'),
    metaRating: extractMetaTag(html, 'rating'),
    metaDescription: extractMetaTag(html, 'description'),
    metaRobots: metaRobots ?? null,
    ogTags: extractOgTags(html),
    twitterCards: extractTwitterCards(html),
    canonicalUrl: extractLink(html, 'canonical'),
    scriptSources: extractAttributes(html, /<script[^>]+src=['"]([^'"]+)['"]/gi),
    stylesheetSources: extractStylesheets(html),
    htmlLang: extractAttribute(html, /<html[^>]+lang=['"]([^'"]+)['"]/i),
    headStructureHash: hashHeadStructure(html),
    bodyStructureHash: hashBodyStructure(html),
    inlineScriptHashes: extractInlineHashes(html, /<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi),
    inlineStyleHashes: extractInlineHashes(html, /<style[^>]*>([\s\S]*?)<\/style>/gi),
    comments: extractComments(html),
    jsonLd: extractJsonLd(html),
    formEndpoints: extractFormEndpoints(html),
    emails: extractEmails(html),
  };
}

function extractMeta(html: string, pattern: RegExp): string | null {
  const match = html.match(pattern);
  return match?.[1]?.trim() ?? null;
}

function extractMetaTag(html: string, name: string): string | null {
  // Match both name= and property= variants
  // Use quote-aware capture: content="..." only stops at ", content='...' only stops at '
  // This handles apostrophes in values like "don't" inside double-quoted attributes
  const esc = escapeRegex(name);
  const patterns = [
    new RegExp(`<meta[^>]+name=["']${esc}["'][^>]+content="([^"]*)"`, 'i'),
    new RegExp(`<meta[^>]+name=["']${esc}["'][^>]+content='([^']*)'`, 'i'),
    new RegExp(`<meta[^>]+content="([^"]*)"[^>]+name=["']${esc}["']`, 'i'),
    new RegExp(`<meta[^>]+content='([^']*)'[^>]+name=["']${esc}["']`, 'i'),
  ];
  for (const p of patterns) {
    const match = html.match(p);
    if (match?.[1]) return decodeHtmlEntities(match[1].trim());
  }
  return null;
}

function extractOgTags(html: string): Record<string, string> {
  const tags: Record<string, string> = {};
  // Quote-aware: match "..." or '...' separately so apostrophes in values don't break capture
  const patterns = [
    /<meta[^>]+property="(og:[^"]+)"[^>]+content="([^"]*)"/gi,
    /<meta[^>]+property='(og:[^']+)'[^>]+content='([^']*)'/gi,
    /<meta[^>]+content="([^"]*)"[^>]+property="(og:[^"]+)"/gi,
    /<meta[^>]+content='([^']*)'[^>]+property='(og:[^']+)'/gi,
  ];
  for (const re of patterns) {
    let match: RegExpExecArray | null;
    while ((match = re.exec(html)) !== null) {
      if (re.source.startsWith('<meta[^>]+content')) {
        if (match[2] && match[1]) tags[match[2]] = match[1];
      } else {
        if (match[1] && match[2]) tags[match[1]] = match[2];
      }
    }
  }
  return tags;
}

function extractTwitterCards(html: string): Record<string, string> {
  const tags: Record<string, string> = {};
  // name="twitter:*" content="..." (either attribute order, quote-aware)
  const patterns = [
    /<meta[^>]+name="(twitter:[^"]+)"[^>]+content="([^"]*)"/gi,
    /<meta[^>]+name='(twitter:[^']+)'[^>]+content='([^']*)'/gi,
    /<meta[^>]+content="([^"]*)"[^>]+name="(twitter:[^"]+)"/gi,
    /<meta[^>]+content='([^']*)'[^>]+name='(twitter:[^']+)'/gi,
  ];
  for (const re of patterns) {
    let match: RegExpExecArray | null;
    while ((match = re.exec(html)) !== null) {
      if (re.source.includes('content=') && re.source.indexOf('content=') < re.source.indexOf('name=')) {
        // content-first pattern: group 1=value, group 2=name
        if (match[2] && match[1]) tags[match[2]] = match[1];
      } else {
        // name-first pattern: group 1=name, group 2=value
        if (match[1] && match[2]) tags[match[1]] = match[2];
      }
    }
  }
  return tags;
}

function extractLink(html: string, rel: string): string | null {
  const re = new RegExp(`<link[^>]+rel=['"]${escapeRegex(rel)}['"][^>]+href=['"]([^'"]+)['"]/?>`, 'i');
  const match = html.match(re);
  return match?.[1] ?? null;
}

function extractAttributes(html: string, pattern: RegExp): string[] {
  const results: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(html)) !== null) {
    if (match[1]) results.push(match[1]);
  }
  return results;
}

function extractStylesheets(html: string): string[] {
  const results: string[] = [];
  // Match <link> tags that have rel="stylesheet" — handle any attribute order
  const linkRe = /<link\b([^>]*)>/gi;
  let match: RegExpExecArray | null;
  while ((match = linkRe.exec(html)) !== null) {
    const attrs = match[1] ?? '';
    if (/rel=['"]stylesheet['"]/i.test(attrs)) {
      const href = attrs.match(/href=['"]([^'"]+)['"]/i);
      if (href?.[1]) results.push(href[1]);
    }
  }
  return results;
}

function extractAttribute(html: string, pattern: RegExp): string | null {
  const match = html.match(pattern);
  return match?.[1] ?? null;
}

function hashHeadStructure(html: string): string {
  const head = html.match(/<head[^>]*>([\s\S]*?)<\/head>/i)?.[1] ?? '';
  // Extract tag names in order (structure, not content)
  const tags = head.match(/<[a-z][a-z0-9]*/gi)?.join(',') ?? '';
  return shortHash(tags);
}

function hashBodyStructure(html: string): string {
  const body = html.match(/<body[^>]*>([\s\S]*?)<\/body>/i)?.[1] ?? '';
  // Extract top-level structural elements
  const structure = body
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .match(/<(?:header|nav|main|section|article|aside|footer|div)[^>]*/gi)
    ?.map((tag) => {
      // Keep tag name + class/id for structure fingerprinting
      const name = tag.match(/<([a-z]+)/i)?.[1] ?? '';
      const cls = tag.match(/class=['"]([^'"]+)['"]/i)?.[1] ?? '';
      const id = tag.match(/id=['"]([^'"]+)['"]/i)?.[1] ?? '';
      return `${name}:${cls}:${id}`;
    })
    .join('|') ?? '';
  return shortHash(structure);
}

function extractInlineHashes(html: string, pattern: RegExp): string[] {
  const hashes: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(html)) !== null) {
    const content = match[1]?.trim();
    if (content && content.length > 10) {
      hashes.push(shortHash(content));
    }
  }
  return hashes;
}

/**
 * True for comments that carry human-readable content. Framework markers —
 * React/Next Suspense & hydration boundaries (`<!--$-->`, `<!--/$-->`,
 * `<!--$?-->`, `<!--$!-->`), Angular/Vue anchors (`<!---->`, `<!--[-->`,
 * `<!--]-->`), whitespace-only comments — are emitted on every page of the
 * framework and leak nothing, so they must not count as an OPSEC signal nor as
 * a shared-comment correlation hit. Anything without a run of ≥3 letters is
 * treated as a marker.
 */
export function isMeaningfulComment(comment: string): boolean {
  return /[A-Za-z\u00C0-\u024F\u0400-\u04FF]{3,}/.test(comment);
}

function extractComments(html: string): string[] {
  const comments: string[] = [];
  const re = /<!--([\s\S]*?)-->/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const comment = match[1]?.trim();
    if (comment && isMeaningfulComment(comment)) comments.push(comment);
  }
  return comments;
}

// Third-party form/booking services whose action URLs or embed URLs are fingerprints
const FORM_ENDPOINT_PATTERNS = [
  /action=['"]([^'"]*formspree\.io[^'"]*)['"]/gi,
  /action=['"]([^'"]*formsubmit\.co[^'"]*)['"]/gi,
  /action=['"]([^'"]*getform\.io[^'"]*)['"]/gi,
  /action=['"]([^'"]*typeform\.com[^'"]*)['"]/gi,
  /action=['"]([^'"]*netlify[^'"]*)['"]/gi,
  /src=['"]([^'"]*calendly\.com\/[^'"]+)['"]/gi,
  /href=['"]([^'"]*calendly\.com\/[^'"]+)['"]/gi,
  /data-url=['"]([^'"]*calendly\.com\/[^'"]+)['"]/gi,
  /src=['"]([^'"]*tally\.so\/[^'"]+)['"]/gi,
  /action=['"]([^'"]*basin\.io[^'"]*)['"]/gi,
  /action=['"]([^'"]*fabform\.io[^'"]*)['"]/gi,
  // Detect Formspree/Calendly URLs in inline JS (fetch-based submissions)
  /['"]+(https:\/\/formspree\.io\/f\/[a-z0-9]+)['"]/gi,
  /['"]+(https:\/\/calendly\.com\/[^'"]+)['"]/gi,
];

function extractFormEndpoints(html: string): string[] {
  const endpoints = new Set<string>();
  for (const pattern of FORM_ENDPOINT_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = re.exec(html)) !== null) {
      if (match[1]) endpoints.add(match[1]);
    }
  }
  return [...endpoints];
}

const EMAIL_RE = /[\w.+-]+@[\w-]+\.[\w.-]+/g;
const MAX_EMAILS = 20;

/** Email addresses exposed anywhere on the page — mailto: links and bare
 *  addresses in body text (nav/footer contact info, unmasked support emails). */
function extractEmails(html: string): string[] {
  const emails = new Set<string>();
  const mailtoRe = /mailto:([^"'?\s]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = mailtoRe.exec(html)) !== null) {
    if (m[1]) emails.add(decodeHtmlEntities(m[1]).toLowerCase());
  }
  const text = html.replace(/<[^>]+>/g, ' ');
  let em: RegExpExecArray | null;
  const bareRe = new RegExp(EMAIL_RE.source, 'g');
  while ((em = bareRe.exec(text)) !== null) {
    emails.add(em[0].toLowerCase());
  }
  return [...emails].slice(0, MAX_EMAILS);
}

function extractJsonLd(html: string): JsonLdData[] {
  const results: JsonLdData[] = [];
  const re = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const raw = match[1]?.trim();
    if (!raw) continue;
    try {
      const data = JSON.parse(raw);
      // Handle both single objects and @graph arrays
      const items = data['@graph'] ? data['@graph'] : [data];
      for (const item of items) {
        const sameAs = Array.isArray(item.sameAs) ? item.sameAs : item.sameAs ? [item.sameAs] : [];
        results.push({
          type: item['@type'] ?? null,
          name: item.name ?? null,
          url: item.url ?? null,
          sameAs: sameAs.filter((s: unknown) => typeof s === 'string'),
        });
      }
    } catch {
      // Malformed JSON-LD — skip
    }
  }
  return results;
}
