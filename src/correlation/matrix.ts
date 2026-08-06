import type { ScanResult, CorrelationFinding, Severity } from '../types.js';

// WHOIS privacy placeholders — these appear on every privacy-protected domain
// and must not be treated as a shared registrant signal
const WHOIS_PRIVACY_PLACEHOLDERS = [
  'data redacted',
  'redacted for privacy',
  'contact privacy',
  'identity protection',
  'privacy protect',
  'whoisguard',
  'domains by proxy',
  'domain privacy',
  'withheld for privacy',
  'statutory masking enabled',
  'not disclosed',
  'private registration',
  'privacy service',
  'redacted by central nic',
  'redacted | eu tied',
];

// Known CDN/third-party script domains — shared scripts from these are expected
// and should not be treated as strong correlation signals
const KNOWN_CDN_PATTERNS = [
  /cloudflareinsights\.com/i,
  /cdnjs\.cloudflare\.com/i,
  /cdn\.jsdelivr\.net/i,
  /unpkg\.com/i,
  /ajax\.googleapis\.com/i,
  /fonts\.googleapis\.com/i,
  /cdn\.tailwindcss\.com/i,
  /polyfill\.io/i,
  /googletagmanager\.com/i,
  /google-analytics\.com/i,
  /connect\.facebook\.net/i,
  /platform\.twitter\.com/i,
  /cdn\.segment\.com/i,
  /js\.stripe\.com/i,
  /cdn\.plyr\.io/i,
  /cdn\.ampproject\.org/i,
];

function isWhoisPrivacyPlaceholder(org: string): boolean {
  const lower = org.toLowerCase().trim();
  return WHOIS_PRIVACY_PLACEHOLDERS.some((p) => lower.includes(p));
}

// Computes pairwise similarity between all scanned domains
// Returns findings (problems) and a similarity matrix

export interface CorrelationOptions {
  verbose?: boolean;
}

export function computeCorrelation(
  results: ScanResult[],
  clusters?: Record<string, string[]>,
  options?: CorrelationOptions,
): { findings: CorrelationFinding[]; matrix: Record<string, Record<string, number>> } {
  const verbose = options?.verbose ?? false;
  const findings: CorrelationFinding[] = [];
  const matrix: Record<string, Record<string, number>> = {};

  // Initialize matrix
  for (const r of results) {
    matrix[r.domain] = {};
    for (const r2 of results) {
      matrix[r.domain][r2.domain] = r.domain === r2.domain ? 100 : 0;
    }
  }

  // Pre-compute fleet-wide analytics IDs (appearing on 3+ sites)
  // so we can suppress pairwise findings for these and avoid double-counting
  const fleetWideIds = new Set<string>();
  {
    const idSiteCounts: Record<string, number> = {};
    for (const r of results) {
      if (!r.analytics) continue;
      const umamiIds = r.analytics.umami.map((u) => u.websiteId).filter(Boolean);
      for (const id of [...r.analytics.ga4, ...r.analytics.adsense, ...r.analytics.gtm, ...r.analytics.cloudflare, ...umamiIds]) {
        idSiteCounts[id] = (idSiteCounts[id] || 0) + 1;
      }
    }
    for (const [id, count] of Object.entries(idSiteCounts)) {
      if (count >= 3) fleetWideIds.add(id);
    }
  }

  // Pre-compute cluster map for O(1) lookups instead of repeated linear scans
  const clusterMap = clusters ? buildClusterMap(clusters) : new Map<string, string>();
  const sameCluster = (da: string, db: string): boolean => {
    const ca = clusterMap.get(da);
    return ca != null && ca === clusterMap.get(db);
  };

  // Pairwise comparison
  for (let i = 0; i < results.length; i++) {
    for (let j = i + 1; j < results.length; j++) {
      const a = results[i];
      const b = results[j];
      const pair = [a.domain, b.domain];
      let similarity = 0;

      // ── IP address (same IP = obvious link) ──
      if (a.dns?.a?.length && b.dns?.a?.length) {
        const shared = a.dns.a.filter((ip) => b.dns!.a.includes(ip));
        if (shared.length > 0) {
          similarity += 15;
          const inSameCluster = sameCluster(a.domain, b.domain);
          if (!inSameCluster) {
            findings.push(finding('shared-ip', 'high', pair,
              `Shared IP address across clusters: ${shared.join(', ')}`,
              `${a.domain} and ${b.domain} resolve to same IP`));
          } else {
            // Same cluster sharing IP is expected but still a signal
            findings.push(finding('shared-ip-same-cluster', 'low', pair,
              `Shared IP (same cluster): ${shared.join(', ')}`,
              `Expected for same-cluster sites but visible to outsiders`));
          }
        }
      }

      // ── Nameservers ──
      if (a.dns?.ns?.length && b.dns?.ns?.length) {
        const sharedNs = a.dns.ns.filter((ns) => b.dns!.ns.includes(ns));
        if (sharedNs.length > 0) {
          similarity += 2; // Commodity: Cloudflare/Route53 NS shared by millions
          // Only flag if different clusters
          if (!sameCluster(a.domain, b.domain)) {
            findings.push(finding('shared-nameservers', 'low', pair,
              `Shared nameservers: ${sharedNs.join(', ')}`,
              `Common with Cloudflare — low signal alone`));
          }
        }
      }

      // ── MX records ──
      if (a.dns?.mx?.length && b.dns?.mx?.length) {
        const aMx = a.dns.mx.map((m) => m.exchange.toLowerCase());
        const bMx = b.dns.mx.map((m) => m.exchange.toLowerCase());
        const sharedMx = aMx.filter((m) => bMx.includes(m));
        if (sharedMx.length > 0) {
          similarity += 4; // Commodity: Google/Microsoft MX shared by millions
          const mxSameCluster = sameCluster(a.domain, b.domain);
          findings.push(finding('shared-mx', mxSameCluster ? 'low' : 'medium', pair,
            `Shared MX records: ${sharedMx.join(', ')}`,
            mxSameCluster ? `Expected for same-cluster sites` : `Email infrastructure correlation`));
        }
      }

      // ── TXT records (verification IDs) ──
      if (a.dns?.txt?.length && b.dns?.txt?.length) {
        // Filter out common infrastructure TXT records that aren't unique signals
        const isTxtInfra = (t: string) => /^v=(spf|dmarc|dkim|tlsrptv)/i.test(t);
        const aTxtSet = new Set(a.dns.txt.filter((t) => !isTxtInfra(t)));
        for (const bTxt of b.dns.txt) {
          if (!isTxtInfra(bTxt) && aTxtSet.has(bTxt)) {
            similarity += 20;
            findings.push(finding('shared-dns-txt', 'high', pair,
              `Identical DNS TXT record: ${bTxt.slice(0, 80)}`,
              `Verification IDs link domains to same account`));
          }
        }
      }

      // ── Analytics IDs (CRITICAL — same GA4/AdSense = game over) ──
      // Skip pairwise findings for IDs already covered by fleet-wide findings to avoid double-counting
      if (a.analytics && b.analytics) {
        for (const gaId of a.analytics.ga4) {
          if (b.analytics.ga4.includes(gaId)) {
            similarity += 40;
            if (!fleetWideIds.has(gaId)) {
              findings.push(finding('shared-ga4', 'critical', pair,
                `SHARED GA4 ID: ${gaId}`,
                `Same Google Analytics property = definitive link`));
            }
          }
        }
        for (const adsId of a.analytics.adsense) {
          if (b.analytics.adsense.includes(adsId)) {
            similarity += 40;
            if (!fleetWideIds.has(adsId)) {
              findings.push(finding('shared-adsense', 'critical', pair,
                `SHARED ADSENSE PUB ID: ${adsId}`,
                `Same AdSense publisher = definitive link`));
            }
          }
        }
        for (const gtmId of a.analytics.gtm) {
          if (b.analytics.gtm.includes(gtmId)) {
            similarity += 30;
            if (!fleetWideIds.has(gtmId)) {
              findings.push(finding('shared-gtm', 'critical', pair,
                `SHARED GTM CONTAINER: ${gtmId}`,
                `Same GTM container = definitive link`));
            }
          }
        }
        for (const umamiA of a.analytics.umami) {
          for (const umamiB of b.analytics.umami) {
            if (umamiA.src === umamiB.src && umamiA.src) {
              similarity += 25;
              findings.push(finding('shared-umami-src', 'high', pair,
                `Same Umami script source: ${umamiA.src}`,
                `Shared self-hosted analytics instance`));
            }
          }
        }
        for (const cfId of a.analytics.cloudflare) {
          if (b.analytics.cloudflare.includes(cfId) && cfId.length >= 20) {
            similarity += 20;
            if (!fleetWideIds.has(cfId)) {
              findings.push(finding('shared-cloudflare-analytics', 'high', pair,
                `Shared Cloudflare Web Analytics token: ${cfId.slice(0, 12)}...`,
                `Same Cloudflare analytics property`));
            }
          }
        }
      }

      // ── TLS certificate ──
      if (a.tls && b.tls) {
        if (a.tls.issuer === b.tls.issuer) {
          similarity += 1; // Very common (Let's Encrypt), negligible signal
        }
        // Check if cert covers both domains (SAN overlap)
        const sharedSan = a.tls.san.filter((s) => b.tls!.san.includes(s));
        if (sharedSan.length > 0) {
          similarity += 35; // Genuine: a multi-domain cert binds the domains together
          findings.push(finding('shared-tls-san', 'critical', pair,
            `TLS cert SAN covers both domains: ${sharedSan.join(', ')}`,
            `Multi-domain cert = definitive link`));
        }
      }

      // ── WHOIS ──
      if (a.whois && b.whois) {
        if (a.whois.registrar && a.whois.registrar === b.whois.registrar) {
          similarity += 3;
        }
        if (a.whois.registrantOrg && a.whois.registrantOrg === b.whois.registrantOrg
          && !isWhoisPrivacyPlaceholder(a.whois.registrantOrg)) {
          similarity += 25;
          findings.push(finding('shared-registrant', 'high', pair,
            `Same registrant org: ${a.whois.registrantOrg}`,
            `WHOIS registrant organization matches`));
        }
        // Registration date proximity (within 7 days)
        if (a.whois.createdDate && b.whois.createdDate) {
          const daysDiff = Math.abs(
            new Date(a.whois.createdDate).getTime() - new Date(b.whois.createdDate).getTime(),
          ) / (1000 * 60 * 60 * 24);
          if (daysDiff < 7) {
            similarity += 10;
            findings.push(finding('registration-proximity', 'medium', pair,
              `Registered ${daysDiff.toFixed(0)} days apart`,
              `Bulk registration pattern`));
          }
        }
      }

      // ── HTML structure ──
      if (a.html && b.html) {
        const sameClusterHtml = sameCluster(a.domain, b.domain);
        if (a.html.headStructureHash === b.html.headStructureHash) {
          similarity += sameClusterHtml ? 1 : 5; // Template-driven (Astro/Next) — modest signal
          // Same-cluster head structure sharing is expected for template sites — don't emit a finding
          if (!sameClusterHtml) {
            const hashSuffix = verbose ? ` (hash: ${a.html.headStructureHash})` : '';
            findings.push(finding('shared-head-structure', 'medium', pair,
              `Identical <head> structure${hashSuffix}`,
              `Same tag order in head = same template`));
          }
        }
        if (a.html.bodyStructureHash === b.html.bodyStructureHash) {
          similarity += 15;
          const hashSuffix = verbose ? ` (hash: ${a.html.bodyStructureHash})` : '';
          findings.push(finding('shared-body-structure', sameClusterHtml ? 'medium' : 'high', pair,
            `Identical <body> structure${hashSuffix}`,
            sameClusterHtml ? `Expected for same-cluster/template sites` : `Same DOM structure = same template/generator`));
        }
        if (a.html.metaGenerator && a.html.metaGenerator === b.html.metaGenerator) {
          similarity += 3; // Commodity: "Astro"/"WordPress" generator shared widely
          findings.push(finding('shared-generator', sameClusterHtml ? 'low' : 'medium', pair,
            `Same meta generator: ${a.html.metaGenerator}`,
            sameClusterHtml ? `Expected for same-cluster sites` : `Generator meta tag fingerprint`));
        }
        // Shared inline script hashes
        if (a.html.inlineScriptHashes.length && b.html.inlineScriptHashes.length) {
          const sharedScripts = a.html.inlineScriptHashes.filter((h) =>
            b.html!.inlineScriptHashes.includes(h));
          if (sharedScripts.length > 0) {
            similarity += 8;
            const hashSuffix = verbose ? `: ${sharedScripts.slice(0, 3).join(', ')}` : '';
            findings.push(finding('shared-inline-scripts', sameClusterHtml ? 'low' : 'medium', pair,
              `${sharedScripts.length} shared inline script hash(es)${hashSuffix}`,
              sameClusterHtml ? `Expected for same-cluster sites` : `Identical inline JavaScript across sites`));
          }
        }
        // Shared JSON-LD sameAs URLs (cross-site ownership signal)
        if (a.html.jsonLd?.length && b.html.jsonLd?.length) {
          const aSameAs = new Set(a.html.jsonLd.flatMap((j) => j.sameAs));
          const bSameAs = new Set(b.html.jsonLd.flatMap((j) => j.sameAs));
          const shared = [...aSameAs].filter((url) => bSameAs.has(url));
          if (shared.length > 0) {
            similarity += 25;
            findings.push(finding('shared-jsonld-sameas', 'high', pair,
              `${shared.length} shared JSON-LD sameAs URL(s): ${shared.slice(0, 3).join(', ')}`,
              `Same social profiles / sameAs links = same entity`));
          }
        }
        // Shared HTML comments
        if (a.html.comments.length && b.html.comments.length) {
          const sharedComments = a.html.comments.filter((c) => b.html!.comments.includes(c));
          if (sharedComments.length > 0) {
            similarity += 5;
            findings.push(finding('shared-comments', 'low', pair,
              `${sharedComments.length} shared HTML comment(s)`,
              `Matching HTML comments across sites`));
          }
        }
      }

      // ── Assets ──
      if (a.assets && b.assets) {
        const sameClusterAssets = sameCluster(a.domain, b.domain);
        if (a.assets.faviconHash && a.assets.faviconHash === b.assets.faviconHash) {
          similarity += 22; // Genuine: identical favicon = same operator
          const hashSuffix = verbose ? ` (hash: ${a.assets.faviconHash})` : '';
          findings.push(finding('shared-favicon', sameClusterAssets ? 'medium' : 'high', pair,
            `Identical favicon${hashSuffix}`,
            sameClusterAssets ? `Expected for same-cluster/brand sites` : `Same favicon file = same operator`));
        }
        // Shared CSS content hashes
        const aCss = new Set(a.assets.cssHashes.map((c) => c.hash));
        const bCss = new Set(b.assets.cssHashes.map((c) => c.hash));
        const sharedCss = [...aCss].filter((h) => bCss.has(h));
        if (sharedCss.length > 0) {
          similarity += 6; // Often a shared CSS framework bundle — moderate signal
          const hashSuffix = verbose ? `: ${sharedCss.slice(0, 3).join(', ')}` : '';
          findings.push(finding('shared-css-hash', sameClusterAssets ? 'low' : 'medium', pair,
            `${sharedCss.length} shared CSS file hash(es)${hashSuffix}`,
            sameClusterAssets ? `Expected for same-cluster sites` : `Identical CSS content across sites`));
        }
        // Shared JS content hashes — split first-party vs third-party CDN scripts
        if (a.assets.jsHashes.length && b.assets.jsHashes.length) {
          const isThirdParty = (url: string) => KNOWN_CDN_PATTERNS.some((p) => p.test(url));
          const aFirst = new Set(a.assets.jsHashes.filter((j) => !isThirdParty(j.url)).map((j) => j.hash));
          const bFirst = new Set(b.assets.jsHashes.filter((j) => !isThirdParty(j.url)).map((j) => j.hash));
          const aThird = new Set(a.assets.jsHashes.filter((j) => isThirdParty(j.url)).map((j) => j.hash));
          const bThird = new Set(b.assets.jsHashes.filter((j) => isThirdParty(j.url)).map((j) => j.hash));
          const sharedFirst = [...aFirst].filter((h) => bFirst.has(h));
          const sharedThird = [...aThird].filter((h) => bThird.has(h));
          if (sharedFirst.length > 0) {
            similarity += 18; // Genuine: identical first-party JS = same build/operator
            const hashSuffix = verbose ? `: ${sharedFirst.slice(0, 3).join(', ')}` : '';
            findings.push(finding('shared-js-hash', sameClusterAssets ? 'medium' : 'high', pair,
              `${sharedFirst.length} shared first-party JS hash(es)${hashSuffix}`,
              sameClusterAssets ? `Expected for same-cluster sites` : `Identical JavaScript content across sites`));
          }
          if (sharedThird.length > 0) {
            similarity += 2; // Commodity: same CDN library across the web
            const hashSuffix = verbose ? `: ${sharedThird.slice(0, 3).join(', ')}` : '';
            findings.push(finding('shared-js-hash-cdn', sameClusterAssets ? 'low' : 'medium', pair,
              `${sharedThird.length} shared third-party CDN JS hash(es)${hashSuffix}`,
              sameClusterAssets ? `Expected — common CDN scripts` : `Same CDN scripts loaded`));
          }
        }
        // Shared font sources — compare by filename (last path segment) to catch
        // same fonts served from different CDN origins
        if (a.assets.fontSources.length && b.assets.fontSources.length) {
          const fontFile = (url: string) => url.split('/').pop()?.split('?')[0] ?? url;
          const aFontFiles = new Set(a.assets.fontSources.map(fontFile));
          const bFontFiles = new Set(b.assets.fontSources.map(fontFile));
          const sharedFonts = [...aFontFiles].filter((f) => bFontFiles.has(f));
          if (sharedFonts.length > 0) {
            similarity += 3; // Commodity: Inter/Roboto and other popular webfonts
            findings.push(finding('shared-fonts', sameClusterAssets ? 'low' : 'medium', pair,
              `${sharedFonts.length} shared font file(s): ${sharedFonts.slice(0, 3).join(', ')}`,
              sameClusterAssets ? `Expected for same-cluster sites` : `Same font files loaded across sites`));
          }
        }
      }

      // ── Shared form/booking endpoints ──
      if (a.html?.formEndpoints?.length && b.html?.formEndpoints?.length) {
        const shared = a.html.formEndpoints.filter((e) => b.html!.formEndpoints.includes(e));
        if (shared.length > 0) {
          similarity += 28; // Genuine: same Formspree/Calendly handle = same operator
          findings.push(finding('shared-form-endpoint', 'high', pair,
            `Shared form endpoint(s): ${shared.slice(0, 3).join(', ')}`,
            `Same third-party form/booking service URL across sites`));
        }
      }

      // ── Shared form/booking provider declared in CSP (homepage-level, no crawl) ──
      if (a.security?.formProviders?.length && b.security?.formProviders?.length) {
        const sharedProviders = a.security.formProviders.filter((p) => b.security!.formProviders.includes(p));
        if (sharedProviders.length > 0) {
          similarity += Math.min(20, 4 + sharedProviders.length * 8);
          findings.push(finding('shared-form-provider', 'medium', pair,
            `Shared form/booking provider(s) in CSP: ${sharedProviders.join(', ')}`,
            `Both declare ${sharedProviders.join(', ')} in Content-Security-Policy — common operator toolkit`));
        }
      }

      // ── Shared twitter:site handle ──
      if (a.html?.twitterCards?.['twitter:site'] && b.html?.twitterCards?.['twitter:site']) {
        if (a.html.twitterCards['twitter:site'] === b.html.twitterCards['twitter:site']) {
          const handle = a.html.twitterCards['twitter:site'];
          similarity += 15;
          findings.push(finding('shared-twitter-site', 'medium', pair,
            `Same twitter:site handle: ${handle}`,
            `Shared Twitter/X account across domains`));
        }
      }

      // ── Robots/ads.txt ──
      if (a.robots && b.robots) {
        if (a.robots.robotsTxtHash && a.robots.robotsTxtHash === b.robots.robotsTxtHash) {
          similarity += 2; // Commodity: default framework robots.txt
          findings.push(finding('shared-robots', 'low', pair,
            `Identical robots.txt`,
            `Same robots.txt content`));
        }
        if (a.robots.adsTxtHash && a.robots.adsTxtHash === b.robots.adsTxtHash) {
          similarity += 15;
          findings.push(finding('shared-ads-txt', 'high', pair,
            `Identical ads.txt`,
            `Same ad publisher declarations`));
        }
        // Shared sitemap URL patterns (same structure = same template)
        if (a.robots.sitemapUrls?.length && b.robots.sitemapUrls?.length) {
          // Compare paths only (strip domain) since domains differ
          const pathOf = (url: string) => { try { return new URL(url).pathname; } catch { return url; } };
          const aPaths = a.robots.sitemapUrls.map(pathOf);
          const bPaths = b.robots.sitemapUrls.map(pathOf);
          const sharedPaths = aPaths.filter((p) => bPaths.includes(p));
          if (sharedPaths.length > 0 && sharedPaths[0] !== '/sitemap.xml') {
            // Only flag non-default sitemap paths as interesting
            similarity += 1; // Commodity: shared sitemap template path
            findings.push(finding('shared-sitemap-structure', 'low', pair,
              `Shared sitemap path(s): ${sharedPaths.join(', ')}`,
              `Same sitemap URL pattern suggests same template/generator`));
          }
        }
        // Shared sitemap content structure
        if (a.robots.sitemapHash && a.robots.sitemapHash === b.robots.sitemapHash) {
          similarity += 2; // Commodity: same sitemap generator (Astro/Next) template
          const hashSuffix = verbose ? ` (hash: ${a.robots.sitemapHash})` : '';
          findings.push(finding('shared-sitemap-hash', 'low', pair,
            `Identical sitemap structure${hashSuffix}`,
            `Same sitemap XML format/template`));
        }
        // Shared ads.txt pub-ids (cross-cluster)
        if (a.robots.adsTxtPubIds?.length && b.robots.adsTxtPubIds?.length) {
          const bPubIdSet = new Set(b.robots.adsTxtPubIds);
          const sharedPubIds = a.robots.adsTxtPubIds.filter((id) => bPubIdSet.has(id));
          if (sharedPubIds.length > 0 && !sameCluster(a.domain, b.domain)) {
            similarity += 20;
            findings.push(finding('shared-ads-txt-pubid-pair', 'high', pair,
              `Shared ads.txt publisher ID(s): ${sharedPubIds.slice(0, 3).join(', ')}`,
              `Same ad publisher IDs in ads.txt across clusters`));
          }
        }
      }

      // ── HTTP headers ──
      if (a.http && b.http) {
        if (a.http.serverHeader && a.http.serverHeader === b.http.serverHeader) {
          similarity += 2; // Commodity: "cloudflare"/"Vercel" server header
        }
        // Shared set-cookie names
        const aCookies = a.http.setCookies.map((c) => c.split('=')[0]);
        const bCookies = b.http.setCookies.map((c) => c.split('=')[0]);
        const sharedCookies = aCookies.filter((c) => bCookies.includes(c));
        if (sharedCookies.length > 0 && sharedCookies[0] !== '') {
          similarity += 3; // Commodity: framework default cookie names
          findings.push(finding('shared-cookies', 'low', pair,
            `Shared cookie names: ${sharedCookies.join(', ')}`,
            `Same cookie names suggest same framework`));
        }
      }

      // Cap at 100
      matrix[a.domain][b.domain] = Math.min(100, similarity);
      matrix[b.domain][a.domain] = Math.min(100, similarity);
    }
  }

  // ── Cross-cluster content leak detection ──
  if (clusters) {
    const clusterMap = buildClusterMap(clusters);
    for (const r of results) {
      const cluster = clusterMap.get(r.domain);
      if (!cluster) continue;

      // Check for adult content on clean cluster sites
      if (!cluster.startsWith('adult') && r.content?.isAdult) {
        findings.push(finding('cross-cluster-adult', 'critical', [r.domain],
          `Adult content detected on clean-cluster site (score: ${r.content.adultScore})`,
          `${r.domain} is in cluster "${cluster}" but has adult signals`));
      }

      // Check for adult ad networks on clean sites
      if (!cluster.startsWith('adult') && r.content?.adNetworks.some((a) => a.isAdult)) {
        const adultAds = r.content!.adNetworks.filter((a) => a.isAdult);
        findings.push(finding('cross-cluster-adult-ads', 'critical', [r.domain],
          `Adult ad network on clean site: ${adultAds.map((a) => a.name).join(', ')}`,
          `${r.domain} is in cluster "${cluster}" but loads adult ad scripts`));
      }

      // Check for adult affiliates on clean sites
      if (!cluster.startsWith('adult') && r.content?.affiliateLinks.some((a) => a.isAdult)) {
        const adultAff = r.content!.affiliateLinks.filter((a) => a.isAdult);
        findings.push(finding('cross-cluster-adult-affiliate', 'critical', [r.domain],
          `Adult affiliate on clean site: ${adultAff.map((a) => a.network).join(', ')}`,
          `${r.domain} is in cluster "${cluster}" but links to adult affiliate networks`));
      }
    }
  }

  // ── Fleet-wide shared analytics (any ID appearing on 3+ sites) ──
  const idCounts: Record<string, string[]> = {};
  for (const r of results) {
    if (!r.analytics) continue;
    const umamiIds = r.analytics.umami.map((u) => u.websiteId).filter(Boolean);
    for (const id of [...r.analytics.ga4, ...r.analytics.adsense, ...r.analytics.gtm, ...r.analytics.cloudflare, ...umamiIds]) {
      if (!idCounts[id]) idCounts[id] = [];
      idCounts[id].push(r.domain);
    }
  }
  for (const [id, domains] of Object.entries(idCounts)) {
    if (domains.length >= 3) {
      findings.push(finding('fleet-wide-tracking-id', 'critical', domains,
        `Tracking ID ${id} found on ${domains.length} sites`,
        `Fleet-wide shared tracking ID: ${domains.join(', ')}`));
    }
  }

  // ── Fleet-wide JSON-LD sameAs (same social profile on 2+ sites) ──
  const sameAsMap: Record<string, string[]> = {};
  for (const r of results) {
    if (!r.html?.jsonLd?.length) continue;
    for (const item of r.html.jsonLd) {
      for (const url of item.sameAs) {
        if (!sameAsMap[url]) sameAsMap[url] = [];
        if (!sameAsMap[url].includes(r.domain)) sameAsMap[url].push(r.domain);
      }
    }
  }
  for (const [url, domains] of Object.entries(sameAsMap)) {
    if (domains.length >= 2) {
      findings.push(finding('fleet-wide-jsonld-sameas', 'high', domains,
        `JSON-LD sameAs URL shared across ${domains.length} sites: ${url}`,
        `Same social profile / identity link: ${domains.join(', ')}`));
    }
  }

  // ── Fleet-wide shared form endpoints (same Formspree/Calendly on 2+ sites) ──
  const formEndpointMap: Record<string, string[]> = {};
  for (const r of results) {
    if (!r.html?.formEndpoints?.length) continue;
    for (const ep of r.html.formEndpoints) {
      if (!formEndpointMap[ep]) formEndpointMap[ep] = [];
      if (!formEndpointMap[ep].includes(r.domain)) formEndpointMap[ep].push(r.domain);
    }
  }
  for (const [ep, domains] of Object.entries(formEndpointMap)) {
    if (domains.length >= 2) {
      findings.push(finding('fleet-wide-form-endpoint', 'high', domains,
        `Form endpoint shared across ${domains.length} sites: ${ep.slice(0, 60)}`,
        `Same form/booking service: ${domains.join(', ')}`));
    }
  }

  // ── Fleet-wide shared form/booking provider (CSP-declared on 2+ sites) ──
  const formProviderMap: Record<string, string[]> = {};
  for (const r of results) {
    for (const provider of r.security?.formProviders ?? []) {
      if (!formProviderMap[provider]) formProviderMap[provider] = [];
      if (!formProviderMap[provider].includes(r.domain)) formProviderMap[provider].push(r.domain);
    }
  }
  for (const [provider, domains] of Object.entries(formProviderMap)) {
    if (domains.length >= 2) {
      findings.push(finding('fleet-wide-form-provider', 'medium', domains,
        `Form/booking provider ${provider} declared in CSP on ${domains.length} sites`,
        `Shared ${provider} integration across: ${domains.join(', ')}`));
    }
  }

  // ── Fleet-wide shared twitter:site handle ──
  const twitterSiteMap: Record<string, string[]> = {};
  for (const r of results) {
    const handle = r.html?.twitterCards?.['twitter:site'];
    if (!handle) continue;
    if (!twitterSiteMap[handle]) twitterSiteMap[handle] = [];
    if (!twitterSiteMap[handle].includes(r.domain)) twitterSiteMap[handle].push(r.domain);
  }
  for (const [handle, domains] of Object.entries(twitterSiteMap)) {
    if (domains.length >= 2) {
      findings.push(finding('fleet-wide-twitter-site', 'medium', domains,
        `twitter:site ${handle} shared across ${domains.length} sites`,
        `Same Twitter/X account: ${domains.join(', ')}`));
    }
  }

  // ── Shared DNS verification tokens (proves same owner) ──
  const googleVerifMap: Record<string, string[]> = {};
  const msVerifMap: Record<string, string[]> = {};
  const fbVerifMap: Record<string, string[]> = {};
  for (const r of results) {
    if (!r.dns) continue;
    if (r.dns.googleVerification) {
      if (!googleVerifMap[r.dns.googleVerification]) googleVerifMap[r.dns.googleVerification] = [];
      googleVerifMap[r.dns.googleVerification].push(r.domain);
    }
    if (r.dns.microsoftVerification) {
      if (!msVerifMap[r.dns.microsoftVerification]) msVerifMap[r.dns.microsoftVerification] = [];
      msVerifMap[r.dns.microsoftVerification].push(r.domain);
    }
    if (r.dns.facebookVerification) {
      if (!fbVerifMap[r.dns.facebookVerification]) fbVerifMap[r.dns.facebookVerification] = [];
      fbVerifMap[r.dns.facebookVerification].push(r.domain);
    }
  }
  for (const [token, domains] of Object.entries(googleVerifMap)) {
    if (domains.length >= 2) {
      findings.push(finding('shared-google-verification', 'critical', domains,
        `Shared Google site verification token: ${token.slice(0, 20)}...`,
        `Same Google Search Console / Workspace account`));
    }
  }
  for (const [token, domains] of Object.entries(msVerifMap)) {
    if (domains.length >= 2) {
      findings.push(finding('shared-ms-verification', 'critical', domains,
        `Shared Microsoft/Bing verification token: ${token.slice(0, 20)}...`,
        `Same Bing Webmaster / Microsoft 365 account`));
    }
  }
  for (const [token, domains] of Object.entries(fbVerifMap)) {
    if (domains.length >= 2) {
      findings.push(finding('shared-facebook-verification', 'critical', domains,
        `Shared Facebook domain verification token: ${token.slice(0, 20)}...`,
        `Same Facebook Business account`));
    }
  }

  // ── Shared ads.txt publisher IDs across clusters ──
  const adsPubIdMap: Record<string, string[]> = {};
  for (const r of results) {
    if (!r.robots?.adsTxtPubIds?.length) continue;
    for (const pubId of r.robots.adsTxtPubIds) {
      if (!adsPubIdMap[pubId]) adsPubIdMap[pubId] = [];
      adsPubIdMap[pubId].push(r.domain);
    }
  }
  for (const [pubId, domains] of Object.entries(adsPubIdMap)) {
    if (domains.length >= 2) {
      // Check if any are cross-cluster
      const crossCluster = hasCrossClusterDomains(domains, clusters);
      if (crossCluster) {
        findings.push(finding('shared-ads-txt-pubid', 'high', domains,
          `Shared ads.txt publisher ID across clusters: ${pubId}`,
          `Same ad publisher ID in ads.txt links domains to same account`));
      }
    }
  }

  // ── Shared affiliate redirect paths across clusters ──
  const affPathMap: Record<string, string[]> = {};
  for (const r of results) {
    if (!r.robots?.affiliateRedirectPaths?.length) continue;
    for (const path of r.robots.affiliateRedirectPaths) {
      if (!affPathMap[path]) affPathMap[path] = [];
      affPathMap[path].push(r.domain);
    }
  }
  for (const [path, domains] of Object.entries(affPathMap)) {
    if (domains.length >= 2 && hasCrossClusterDomains(domains, clusters)) {
      findings.push(finding('shared-affiliate-redirect-path', 'medium', domains,
        `Shared affiliate redirect path across clusters: ${path}`,
        `Same redirect path pattern in robots.txt Disallow`));
    }
  }

  return { findings, matrix };
}

function finding(type: string, severity: Severity, domains: string[], detail: string, evidence: string): CorrelationFinding {
  return { type, severity, domains, detail, evidence };
}

function hasCrossClusterDomains(domains: string[], clusters?: Record<string, string[]>): boolean {
  if (!clusters || domains.length < 2) return false;
  const clusterNames = new Set<string>();
  for (const domain of domains) {
    for (const [name, clusterDomains] of Object.entries(clusters)) {
      if (clusterDomains.includes(domain)) {
        clusterNames.add(name);
        break;
      }
    }
  }
  return clusterNames.size >= 2;
}

function buildClusterMap(clusters: Record<string, string[]>): Map<string, string> {
  const map = new Map<string, string>();
  for (const [name, domains] of Object.entries(clusters)) {
    for (const d of domains) map.set(d, name);
  }
  return map;
}
