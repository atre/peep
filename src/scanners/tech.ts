import type { TechResult, TechDetection, HtmlResult, DnsResult } from '../types.js';

interface TechSignature {
  name: string;
  category: TechDetection['category'];
  detect: (ctx: DetectContext) => { confidence: number; evidence: string } | null;
}

interface DetectContext {
  html: string;
  headers: Record<string, string>;
  htmlResult: HtmlResult | null;
  dnsResult: DnsResult | null;
}

const SIGNATURES: TechSignature[] = [
  // ── Frameworks / SSGs ──
  {
    name: 'Astro',
    category: 'framework',
    detect: (ctx) => {
      if (/\/_astro\//.test(ctx.html)) return { confidence: 95, evidence: '/_astro/ path in assets' };
      if (ctx.htmlResult?.metaGenerator?.toLowerCase().includes('astro')) return { confidence: 100, evidence: 'meta generator' };
      return null;
    },
  },
  {
    name: 'Next.js',
    category: 'framework',
    detect: (ctx) => {
      if (/\/_next\//.test(ctx.html)) return { confidence: 95, evidence: '/_next/ path in assets' };
      if (ctx.headers['x-nextjs-cache']) return { confidence: 100, evidence: 'x-nextjs-cache header' };
      if (ctx.headers['x-powered-by']?.includes('Next.js')) return { confidence: 100, evidence: 'x-powered-by header' };
      return null;
    },
  },
  {
    name: 'Nuxt',
    category: 'framework',
    detect: (ctx) => {
      if (/\/_nuxt\//.test(ctx.html)) return { confidence: 95, evidence: '/_nuxt/ path in assets' };
      if (/__nuxt/.test(ctx.html)) return { confidence: 80, evidence: '__nuxt element in HTML' };
      return null;
    },
  },
  {
    name: 'Gatsby',
    category: 'framework',
    detect: (ctx) => {
      if (ctx.htmlResult?.metaGenerator?.toLowerCase().includes('gatsby')) return { confidence: 100, evidence: 'meta generator' };
      if (/gatsby-/.test(ctx.html) && /___gatsby/.test(ctx.html)) return { confidence: 90, evidence: '___gatsby element' };
      return null;
    },
  },
  {
    name: 'Hugo',
    category: 'framework',
    detect: (ctx) => {
      if (ctx.htmlResult?.metaGenerator?.toLowerCase().includes('hugo')) return { confidence: 100, evidence: 'meta generator' };
      return null;
    },
  },
  {
    name: 'Jekyll',
    category: 'framework',
    detect: (ctx) => {
      if (ctx.htmlResult?.metaGenerator?.toLowerCase().includes('jekyll')) return { confidence: 100, evidence: 'meta generator' };
      return null;
    },
  },
  {
    name: 'WordPress',
    category: 'cms',
    detect: (ctx) => {
      if (ctx.htmlResult?.metaGenerator?.toLowerCase().includes('wordpress')) return { confidence: 100, evidence: 'meta generator' };
      if (/\/wp-content\//.test(ctx.html)) return { confidence: 95, evidence: 'wp-content path' };
      if (/\/wp-includes\//.test(ctx.html)) return { confidence: 95, evidence: 'wp-includes path' };
      return null;
    },
  },
  {
    name: 'Drupal',
    category: 'cms',
    detect: (ctx) => {
      if (ctx.htmlResult?.metaGenerator?.toLowerCase().includes('drupal')) return { confidence: 100, evidence: 'meta generator' };
      if (ctx.headers['x-drupal-cache']) return { confidence: 100, evidence: 'x-drupal-cache header' };
      if (/\/sites\/default\/files\//.test(ctx.html)) return { confidence: 80, evidence: 'Drupal default files path' };
      return null;
    },
  },
  {
    name: 'Squarespace',
    category: 'cms',
    detect: (ctx) => {
      if (/squarespace\.com/.test(ctx.html) || /static1\.squarespace\.com/.test(ctx.html)) return { confidence: 90, evidence: 'squarespace.com in assets' };
      return null;
    },
  },
  {
    name: 'Webflow',
    category: 'cms',
    detect: (ctx) => {
      if (ctx.htmlResult?.metaGenerator?.toLowerCase().includes('webflow')) return { confidence: 100, evidence: 'meta generator' };
      if (/assets\.website-files\.com/.test(ctx.html)) return { confidence: 85, evidence: 'webflow assets CDN' };
      return null;
    },
  },
  {
    name: 'React',
    category: 'framework',
    detect: (ctx) => {
      if (/__react/.test(ctx.html) || /data-reactroot/.test(ctx.html)) return { confidence: 85, evidence: 'React root element' };
      return null;
    },
  },
  {
    name: 'Vue.js',
    category: 'framework',
    detect: (ctx) => {
      if (/data-v-[a-f0-9]/.test(ctx.html)) return { confidence: 85, evidence: 'Vue scoped style attributes' };
      if (ctx.html.includes('__vue_app__')) return { confidence: 90, evidence: '__vue_app__ in HTML' };
      return null;
    },
  },
  {
    name: 'Svelte',
    category: 'framework',
    detect: (ctx) => {
      if (/svelte-[a-z0-9]/.test(ctx.html) && /class="s-/.test(ctx.html)) return { confidence: 80, evidence: 'Svelte class prefixes' };
      return null;
    },
  },

  // ── CSS Frameworks ──
  {
    name: 'Tailwind CSS',
    category: 'framework',
    detect: (ctx) => {
      // Tailwind utility class patterns in HTML
      const twPatterns = /\bclass="[^"]*(?:flex|grid|bg-|text-|px-|py-|mt-|mb-|rounded|shadow|hover:|sm:|md:|lg:)[^"]*"/;
      if (twPatterns.test(ctx.html)) {
        // High confidence if many utility classes present
        const utilityCount = (ctx.html.match(/\b(?:flex|grid|bg-|text-|px-|py-|mt-|mb-|rounded-|shadow-|hover:|sm:|md:|lg:|xl:)\w+/g) || []).length;
        if (utilityCount > 20) return { confidence: 90, evidence: `${utilityCount}+ Tailwind utility classes` };
        if (utilityCount > 5) return { confidence: 70, evidence: `${utilityCount} Tailwind-like utility classes` };
      }
      return null;
    },
  },

  // ── CDN ──
  {
    name: 'Cloudflare',
    category: 'cdn',
    detect: (ctx) => {
      if (ctx.headers['server'] === 'cloudflare') return { confidence: 100, evidence: 'server: cloudflare header' };
      if (ctx.headers['cf-ray']) return { confidence: 100, evidence: 'cf-ray header' };
      return null;
    },
  },
  {
    name: 'Vercel',
    category: 'hosting',
    detect: (ctx) => {
      if (ctx.headers['x-vercel-id']) return { confidence: 100, evidence: 'x-vercel-id header' };
      if (ctx.headers['server'] === 'Vercel') return { confidence: 100, evidence: 'server: Vercel' };
      return null;
    },
  },
  {
    name: 'Netlify',
    category: 'hosting',
    detect: (ctx) => {
      if (ctx.headers['x-nf-request-id']) return { confidence: 100, evidence: 'x-nf-request-id header' };
      if (ctx.headers['server']?.includes('Netlify')) return { confidence: 100, evidence: 'server: Netlify' };
      return null;
    },
  },
  {
    name: 'AWS CloudFront',
    category: 'cdn',
    detect: (ctx) => {
      if (ctx.headers['x-amz-cf-id']) return { confidence: 100, evidence: 'x-amz-cf-id header' };
      if (ctx.headers['via']?.includes('cloudfront')) return { confidence: 90, evidence: 'via: cloudfront' };
      return null;
    },
  },
  {
    name: 'Fastly',
    category: 'cdn',
    detect: (ctx) => {
      if (ctx.headers['x-served-by']?.includes('cache-')) return { confidence: 85, evidence: 'Fastly cache header' };
      if (ctx.headers['via']?.includes('varnish')) return { confidence: 60, evidence: 'via: varnish (possibly Fastly)' };
      return null;
    },
  },

  // ── Hosting ──
  {
    name: 'GitHub Pages',
    category: 'hosting',
    detect: (ctx) => {
      if (ctx.headers['server'] === 'GitHub.com') return { confidence: 100, evidence: 'server: GitHub.com' };
      if (ctx.dnsResult?.cname?.some((c) => c.includes('github.io'))) return { confidence: 95, evidence: 'CNAME to github.io' };
      return null;
    },
  },
  {
    name: 'Cloudflare Pages',
    category: 'hosting',
    detect: (ctx) => {
      if (ctx.headers['cf-ray'] && ctx.headers['server'] === 'cloudflare') {
        let confidence = 0;
        const evidence: string[] = [];

        // CNAME to *.pages.dev is strong signal (may be empty for proxied domains)
        if (ctx.dnsResult?.cname?.some((c) => c.endsWith('.pages.dev'))) {
          confidence = 95;
          evidence.push('CNAME to *.pages.dev');
        }

        // Static site patterns + no server framework = likely Pages
        const hasStaticPatterns = /\/_astro\/|\/build\/|\/assets\//.test(ctx.html);
        if (hasStaticPatterns && !ctx.headers['x-powered-by']) {
          confidence = Math.max(confidence, 60);
          evidence.push('static site patterns');
        }

        // cf-cache-status is set on ANY Cloudflare-proxied origin (Hetzner behind
        // the orange cloud gets it too) — it may only corroborate an existing
        // Pages signal, never stand alone as evidence.
        if (ctx.headers['cf-cache-status'] && confidence > 0) {
          confidence = Math.min(100, confidence + 10);
          evidence.push('cf-cache-status');
        }

        // COOP/COEP/CORP headers set (Pages deploys these by default via _headers)
        const hasCrossOriginHeaders = ctx.headers['cross-origin-opener-policy']
          || ctx.headers['cross-origin-embedder-policy']
          || ctx.headers['cross-origin-resource-policy'];
        if (hasCrossOriginHeaders && hasStaticPatterns) {
          confidence = Math.min(100, confidence + 15);
          evidence.push('cross-origin headers');
        }

        if (confidence > 0) {
          return { confidence: Math.min(100, confidence), evidence: evidence.join(', ') };
        }
      }
      return null;
    },
  },

  // ── Monitoring / Error Logging ──
  {
    name: 'NEL (Network Error Logging)',
    category: 'other',
    detect: (ctx) => {
      if (ctx.headers['nel'] && ctx.headers['report-to']) {
        return { confidence: 100, evidence: 'NEL + Report-To headers' };
      }
      if (ctx.headers['nel']) {
        return { confidence: 90, evidence: 'NEL header present' };
      }
      return null;
    },
  },

  // ── Server ──
  {
    name: 'Nginx',
    category: 'server',
    detect: (ctx) => {
      if (ctx.headers['server']?.toLowerCase().startsWith('nginx')) return { confidence: 100, evidence: `server: ${ctx.headers['server']}` };
      return null;
    },
  },
  {
    name: 'Apache',
    category: 'server',
    detect: (ctx) => {
      if (ctx.headers['server']?.toLowerCase().startsWith('apache')) return { confidence: 100, evidence: `server: ${ctx.headers['server']}` };
      return null;
    },
  },
  {
    name: 'Caddy',
    category: 'server',
    detect: (ctx) => {
      if (ctx.headers['server']?.toLowerCase() === 'caddy') return { confidence: 100, evidence: `server: ${ctx.headers['server']}` };
      return null;
    },
  },
];

export function scanTech(
  html: string,
  headers: Record<string, string>,
  htmlResult: HtmlResult | null,
  dnsResult: DnsResult | null,
): TechResult {
  const technologies: TechDetection[] = [];
  const ctx: DetectContext = { html, headers, htmlResult, dnsResult };

  for (const sig of SIGNATURES) {
    const match = sig.detect(ctx);
    if (match) {
      technologies.push({
        name: sig.name,
        category: sig.category,
        confidence: match.confidence,
        evidence: match.evidence,
      });
    }
  }

  // Sort by confidence descending
  technologies.sort((a, b) => b.confidence - a.confidence);

  return { technologies };
}
