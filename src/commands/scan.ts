import { scanDomain, validateScannerNames, SELECTABLE_SCANNERS } from '../scanners/index.js';
import { analyticsVendors } from '../scanners/analytics.js';
import type { PeepConfig, ScanResult, OutputFormat, RobotsTxtSummary, SecurityTxtSummary, SeoResult, PageAudit } from '../types.js';
import { c, formatDuration, severityColor, getCluster, writeOutputFile, scoreColor, resolveScanningConfig, parsePagesFlag, oneClickDnssecProvider, isAdultCluster, describeHttpStatus, isErrorStatus, emailAuthChecks } from '../utils.js';

export async function cmdScan(
  domains: string[],
  config: PeepConfig,
  flags: Record<string, string | boolean>,
): Promise<void> {
  const format = (flags.format as OutputFormat) || 'text';
  const only = flags.only ? String(flags.only).split(',') : config.scanning.only;
  if (only) {
    const unknown = validateScannerNames(only);
    if (unknown.length > 0) {
      console.error(`Warning: unknown scanner(s) in --only: ${unknown.join(', ')}. Known: ${SELECTABLE_SCANNERS.join(', ')}`);
    }
  }
  const skipWhois = flags['skip-whois'] === true;
  const skipAssets = flags['skip-assets'] === true;
  const scanConfig = resolveScanningConfig(flags, config.scanning);
  const { pages, pageRoutes } = parsePagesFlag(flags);
  const verbose = flags.verbose === true;
  const brief = flags.brief === true;
  const quiet = flags.quiet === true || brief; // --brief implies -q: no "Scanning... done" progress line
  const outFile = flags.out ? String(flags.out) : null;

  const results: ScanResult[] = [];

  for (const domain of domains) {
    if (format === 'text' && !quiet) {
      process.stdout.write(`Scanning ${c('cyan', domain)}...`);
    }

    const result = await scanDomain(domain, {
      config: scanConfig,
      adultScoreThreshold: config.thresholds.adultScore,
      skipWhois,
      skipAssets,
      only,
      pages,
      pageRoutes,
    });

    results.push(result);

    if (format === 'text' && !quiet) {
      const errCount = result.errors.length;
      const errStr = errCount > 0 ? ` ${c('yellow', `(${errCount} errors)`)}` : '';
      const noindexStr = result.isNoindex ? ` ${c('yellow', '[NOINDEX]')}` : '';
      const downStr = isErrorStatus(result.http?.statusCode) ? ` ${c('red', `[HTTP ${result.http!.statusCode}]`)}` : '';
      console.log(` done in ${formatDuration(result.duration)}${errStr}${noindexStr}${downStr}`);
      printScanResult(result, config, verbose, only, skipWhois);
    } else if (format === 'text' && brief) {
      printScanResult(result, config, verbose, only, skipWhois, true);
    }
  }

  const jsonOut = JSON.stringify(results.length === 1 ? results[0] : results, null, 2);

  if (outFile) {
    // scan has no plain-text serialization, so --out always writes JSON
    if (!outFile.endsWith('.json')) {
      console.error(`Note: 'peep scan --out' writes JSON; ${outFile} will contain JSON.`);
    }
    const full = writeOutputFile(outFile, jsonOut);
    if (!quiet) console.error(`\nScan results written to ${c('cyan', full)}`);
  } else if (format === 'json') {
    console.log(jsonOut);
  }

  // Exit code based on findings
  const hasAdultOnClean = results.some((r) => {
    if (!r.content) return false;
    const cluster = getCluster(r.domain, config.fleet.clusters);
    return cluster && !isAdultCluster(cluster) && r.content.isAdult;
  });

  if (hasAdultOnClean) process.exit(2);
}

/** Per-page SEO label: appends "(N/total pass)" so a "92/100" with one `~` line
 *  is self-explanatory. Falls back to the bare score for older JSON without
 *  `seoEvaluated`. */
export function pageSeoLabel(p: PageAudit): string {
  if (p.seoScore === null) return 'SEO n/a';
  if (p.seoEvaluated === undefined) return `SEO ${p.seoScore}/100`;
  const passing = p.seoEvaluated - p.seoIssues.length;
  return `SEO ${p.seoScore}/100 (${passing}/${p.seoEvaluated} pass)`;
}

/** SEO headline: the plain score when a full scan ran, or an "N/total evaluated
 *  (partial)" label when a `--only` selection (or a failed dependency) left some
 *  checks unevaluated — a bare "100/100" there would misread as a full pass.
 *  Checks skipped deliberately (noindex) don't count toward "partial". */
export function seoHeadline(seo: SeoResult | null): string {
  if (!seo) return 'SEO: not scanned';
  if (seo.score === null) return 'SEO not evaluated (fetch failed)';
  const skippedCount = seo.skipped?.length ?? 0;
  if (seo.evaluated + skippedCount < seo.total) {
    return `SEO ${seo.evaluated}/${seo.total} evaluated (partial)`;
  }
  return `SEO ${seo.score}/100`;
}

/** WHOIS section replacement when the scanner was selected/enabled but produced
 *  no usable data — `--only whois` on a scan that failed used to print nothing. */
export function whoisStatusLine(result: ScanResult, only?: string[]): string | null {
  if (only && !only.includes('whois')) return null;
  if (result.whois && (result.whois.registrar || result.whois.createdDate || result.whois.expiryDate)) return null;
  const reason = result.errors.find((e) => e.scanner === 'whois')?.error ?? 'no data found';
  return `WHOIS: unavailable (${reason})`;
}

/** Red-only summary for gate/hook use: at most 10 lines — header (domain +
 *  SEO/SEC scores + NOINDEX/HTTP-error flags), then only missing/bad checks
 *  and scan errors. Warnings and good/`+` lines are deliberately dropped. */
export function briefLines(r: ScanResult): string[] {
  const flags: string[] = [];
  if (r.isNoindex) flags.push('[NOINDEX]');
  if (isErrorStatus(r.http?.statusCode)) flags.push(`[HTTP ${r.http!.statusCode}]`);
  const headerParts = [r.domain];
  if (r.seo?.score != null) headerParts.push(`SEO ${r.seo.score}`);
  if (r.security?.score != null) headerParts.push(`SEC ${r.security.score}`);
  const header = [headerParts.join('  '), ...flags].join('  ');

  const isRed = (rating: string) => rating === 'missing' || rating === 'bad';
  const details: string[] = [];
  for (const check of r.seo?.checks ?? []) {
    if (isRed(check.rating)) details.push(`  - ${check.name}: ${check.detail}`);
  }
  for (const h of r.security?.headers ?? []) {
    if (isRed(h.rating)) details.push(`  - ${h.name}: ${h.detail}`);
  }
  for (const ch of emailAuthChecks(r.dns) ?? []) {
    if (isRed(ch.rating)) details.push(`  - ${ch.name}: ${ch.detail}`);
  }
  for (const e of r.errors) {
    details.push(`  ! [${e.scanner}] ${e.error}`);
  }

  const bodyBudget = 9; // 10 total minus the header line
  if (details.length > bodyBudget) {
    const shown = details.slice(0, bodyBudget - 1);
    shown.push(`  … +${details.length - (bodyBudget - 1)} more`);
    return [header, ...shown];
  }
  return [header, ...details];
}

function printScanResult(result: ScanResult, config: PeepConfig, verbose = false, only?: string[], skipWhois = false, brief = false): void {
  if (brief) {
    for (const line of briefLines(result)) console.log(line);
    return;
  }

  console.log('');

  // Error response (prominent) — everything below reflects the error page,
  // not the site: security score is Cloudflare's, SEO is 0, content is empty.
  if (isErrorStatus(result.http?.statusCode)) {
    const code = result.http!.statusCode;
    console.log(c('red', `  ✗ HTTP ${code} — ${describeHttpStatus(code)}`));
    console.log(c('dim', '    Scores below describe the error response, not the site.'));
  }

  // Noindex status (prominent)
  if (result.isNoindex) {
    console.log(c('yellow', '  ⚠ NOINDEX — site is not indexable by search engines (placeholder/staging)'));
  }

  // DNS
  if (result.dns) {
    console.log(c('bold', '  DNS'));
    if (result.dns.a.length) console.log(`    A:  ${result.dns.a.join(', ')}`);
    if (result.dns.aaaa.length) console.log(`    AAAA: ${result.dns.aaaa.join(', ')}`);
    if (result.dns.mx.length) console.log(`    MX: ${result.dns.mx.map((m) => `${m.exchange} (${m.priority})`).join(', ')}`);
    if (result.dns.ns.length) console.log(`    NS: ${result.dns.ns.join(', ')}`);
    if (result.dns.txt.length) console.log(`    TXT: ${result.dns.txt.join(', ')}`);
    if (result.dns.cname.length) console.log(`    CNAME: ${result.dns.cname.join(', ')}`);
    if (result.dns.caa?.length) console.log(`    CAA: ${result.dns.caa.join(', ')}`);
    const email = emailAuthChecks(result.dns);
    if (email) {
      for (const e of email) {
        const icon = e.rating === 'good' ? c('green', '+') : e.rating === 'missing' || e.rating === 'bad' ? c('red', '-') : c('yellow', '~');
        const detail = e.rating === 'good' ? c('dim', e.detail) : c('yellow', e.detail);
        console.log(`    ${icon} ${e.name}: ${e.value} ${c('dim', '—')} ${detail}`);
      }
    }
  }

  // HTTP
  if (result.http) {
    console.log(c('bold', '  HTTP'));
    console.log(`    Status: ${result.http.statusCode}`);
    if (result.http.serverHeader) console.log(`    Server: ${result.http.serverHeader}`);
    if (result.http.poweredBy) console.log(`    X-Powered-By: ${result.http.poweredBy}`);
    console.log(`    Timing: ${formatDuration(result.http.timing)}`);
    if (result.http.redirectChain.length > 0) {
      console.log(`    Redirects: ${result.http.redirectChain.join(' → ')}`);
    }
    console.log(`    Accept-Language: ${result.http.acceptLanguage ?? c('dim', '(none sent)')}`);
    if (result.http.setCookies.length > 0) {
      console.log(`    Cookies: ${result.http.setCookies.length} set-cookie header(s)`);
      for (const cookie of result.http.setCookies) {
        const name = cookie.split('=')[0];
        console.log(`      ${c('dim', name)}`);
      }
    }
  }

  // TLS
  if (result.tls) {
    console.log(c('bold', '  TLS'));
    console.log(`    Issuer: ${result.tls.issuer}`);
    console.log(`    Protocol: ${result.tls.protocol}`);
    console.log(`    Cipher: ${result.tls.cipher}`);
    console.log(`    SAN: ${result.tls.san.slice(0, 5).join(', ')}${result.tls.san.length > 5 ? ` (+${result.tls.san.length - 5} more)` : ''}`);
    console.log(`    Fingerprint: ${result.tls.fingerprint}`);
    if (result.tls.daysUntilExpiry !== null) {
      const days = result.tls.daysUntilExpiry;
      let expiryStr: string;
      if (days < 0) expiryStr = c('red', `EXPIRED ${Math.abs(days)} days ago`);
      else if (days <= 14) expiryStr = c('red', `${days} days (critical)`);
      else if (days <= 30) expiryStr = c('yellow', `${days} days (warning)`);
      else expiryStr = c('green', `${days} days`);
      console.log(`    Expires in: ${expiryStr}`);
    }
  }

  // WHOIS
  if (result.whois) {
    console.log(c('bold', '  WHOIS'));
    if (result.whois.registrar) console.log(`    Registrar: ${result.whois.registrar}`);
    if (result.whois.createdDate) console.log(`    Created: ${result.whois.createdDate}`);
    if (result.whois.expiryDate) console.log(`    Expires: ${result.whois.expiryDate}`);
    if (result.whois.nameservers.length) console.log(`    NS: ${result.whois.nameservers.join(', ')}`);
    if (result.whois.registrantOrg) console.log(`    Organization: ${result.whois.registrantOrg}`);
    if (result.whois.registrantCountry) console.log(`    Country: ${result.whois.registrantCountry}`);
    if (result.whois.dnssec) {
      const unsigned = /unsigned/i.test(result.whois.dnssec);
      const provider = unsigned
        ? oneClickDnssecProvider([...result.whois.nameservers, ...(result.dns?.ns ?? [])])
        : null;
      if (provider) {
        console.log(`    ${c('yellow', `⚠ DNSSEC: ${result.whois.dnssec} — ${provider} supports one-click DNSSEC; enabling it blocks DNS spoofing / cache poisoning`)}`);
      } else {
        console.log(`    DNSSEC: ${result.whois.dnssec}`);
      }
    }
  } else if (!skipWhois) {
    const line = whoisStatusLine(result, only);
    if (line) console.log(`  ${c('yellow', line)}`);
  }

  // HTML metadata
  if (result.html) {
    console.log(c('bold', '  HTML'));
    if (result.html.title) console.log(`    Title: ${result.html.title}`);
    if (result.html.metaDescription) console.log(`    Description: ${result.html.metaDescription.slice(0, 100)}${result.html.metaDescription.length > 100 ? '...' : ''}`);
    if (result.html.htmlLang) console.log(`    Language: ${result.html.htmlLang}`);
    if (result.html.metaGenerator) console.log(`    Generator: ${result.html.metaGenerator}`);
    if (result.html.canonicalUrl) console.log(`    Canonical: ${result.html.canonicalUrl}`);
    const ogKeys = Object.keys(result.html.ogTags);
    if (ogKeys.length > 0) {
      console.log(`    OG Tags: ${ogKeys.join(', ')}`);
    }
    const twKeys = Object.keys(result.html.twitterCards ?? {});
    if (twKeys.length > 0) {
      console.log(`    Twitter Cards: ${twKeys.join(', ')}`);
    }
    if (result.html.scriptSources.length) {
      console.log(`    Scripts (${result.html.scriptSources.length}): ${result.html.scriptSources.map(shortenUrl).join(', ')}`);
    }
    if (result.html.stylesheetSources.length) {
      console.log(`    Stylesheets (${result.html.stylesheetSources.length}): ${result.html.stylesheetSources.map(shortenUrl).join(', ')}`);
    }
    if (result.html.comments.length) {
      console.log(`    HTML comments: ${result.html.comments.length}`);
    }
    if (result.html.jsonLd.length) {
      console.log(`    JSON-LD (${result.html.jsonLd.length}):`);
      for (const item of result.html.jsonLd) {
        const parts = [item.type, item.name].filter(Boolean).join(' — ');
        console.log(`      ${parts || '(unknown type)'}`);
        if (item.sameAs.length > 0) {
          for (const url of item.sameAs) {
            console.log(`        sameAs: ${c('dim', url)}`);
          }
        }
      }
    }
    if (result.html.formEndpoints?.length) {
      console.log(`    Form endpoints (${result.html.formEndpoints.length}): ${result.html.formEndpoints.map(shortenUrl).join(', ')}`);
    }
  }

  // Analytics
  if (result.analytics) {
    const a = result.analytics;
    const hasAny = a.ga4.length || a.gtm.length || a.adsense.length || a.umami.length || a.cloudflare.length || a.facebook.length || a.clarity.length || a.plausible.length || a.other.length;
    if (hasAny) {
      console.log(c('bold', '  Analytics / Tracking'));
      const vendors = analyticsVendors(a);
      if (vendors.length >= 2) console.log(`    ${c('cyan', `${vendors.length} analytics vendors (${vendors.join(', ')})`)}`);
      if (a.ga4.length) console.log(`    GA4: ${a.ga4.join(', ')}`);
      if (a.gtm.length) console.log(`    GTM: ${a.gtm.join(', ')}`);
      if (a.adsense.length) console.log(`    AdSense: ${a.adsense.join(', ')}`);
      if (a.umami.length) console.log(`    Umami: ${a.umami.map((u) => u.websiteId).join(', ')}`);
      if (a.cloudflare.length) console.log(`    Cloudflare Web Analytics: ${a.cloudflare.join(', ')}`);
      if (a.facebook.length) console.log(`    Facebook Pixel: ${a.facebook.join(', ')}`);
      if (a.clarity.length) console.log(`    Clarity: ${a.clarity.join(', ')}`);
      if (a.plausible.length) console.log(`    Plausible: ${a.plausible.join(', ')}`);
      for (const o of a.other) console.log(`    ${o.name}: ${o.id}`);
    } else {
      console.log(c('bold', '  Analytics / Tracking'));
      console.log(`    ${c('dim', '(none detected)')}`);
    }
  }

  // Assets
  if (result.assets) {
    console.log(c('bold', '  Assets'));
    if (result.assets.faviconUrl) {
      const hash = result.assets.faviconHash ? `hash: ${result.assets.faviconHash}` : c('yellow', 'declared but not fetchable');
      console.log(`    Favicon: ${shortenUrl(result.assets.faviconUrl)} (${hash})`);
    } else {
      console.log(`    Favicon: ${c('dim', 'none')}`);
    }
    console.log(`    CSS files: ${result.assets.cssHashes.length}${result.assets.cssHashes.length > 0 ? ` — ${result.assets.cssHashes.map((h) => shortenUrl(h.url)).join(', ')}` : ''}`);
    console.log(`    JS files: ${result.assets.jsHashes.length}${result.assets.jsHashes.length > 0 ? ` — ${result.assets.jsHashes.map((h) => shortenUrl(h.url)).join(', ')}` : ''}`);
    if (result.assets.fontFamilies.length) console.log(`    Fonts: ${result.assets.fontFamilies.join(', ')}`);
    if (result.assets.fontSources.length) console.log(`    Font files: ${result.assets.fontSources.map(shortenUrl).join(', ')}`);
    console.log(`    Images: ${result.assets.imageCount} in page${result.assets.ogImages.length > 0 ? ` + ${result.assets.ogImages.length} OG/meta` : ''}`);
    if (result.assets.ogImages.length > 0) {
      for (const img of result.assets.ogImages) {
        console.log(`      ${c('dim', shortenUrl(img))}`);
      }
    }
  }

  // Robots / well-known files
  if (result.robots) {
    console.log(c('bold', '  Robots & Well-Known'));
    console.log(`    robots.txt: ${result.robots.robotsTxt ? c('green', 'present') : c('dim', 'absent')}${result.robots.robotsTxtHash ? ` (hash: ${result.robots.robotsTxtHash})` : ''}${formatRobotsSummary(result.robots.robotsSummary)}`);
    if (result.robots.sitemapUrls.length) console.log(`    Sitemap: ${result.robots.sitemapUrls.join(', ')}`);
    const adsFacts = result.robots.adsTxt && result.robots.adsTxtPubIds.length
      ? ` — ${result.robots.adsTxtPubIds.length} pub-id(s): ${result.robots.adsTxtPubIds.slice(0, 3).join(', ')}`
      : '';
    console.log(`    ads.txt: ${result.robots.adsTxt ? c('green', 'present') : c('dim', 'absent')}${adsFacts}`);
    console.log(`    security.txt: ${result.robots.securityTxt ? c('green', 'present') : c('yellow', 'absent')}${formatSecurityTxtSummary(result.robots.securityTxtSummary)}`);
    const h = result.robots.humansTxtSummary;
    const humansFacts = h ? ` — ${h.lines} lines${h.contact ? `, Contact: ${h.contact}` : ''}` : '';
    console.log(`    humans.txt: ${result.robots.humansTxt ? c('green', 'present') : c('dim', 'absent')}${humansFacts}`);
  }

  // Security headers
  if (result.security) {
    console.log(c('bold', '  Security Headers') + ` ${c(scoreColor(result.security.score), `(${result.security.score}/100)`)}`);
    for (const h of result.security.headers) {
      const icon = h.rating === 'good' ? c('green', '+') : h.rating === 'warning' ? c('yellow', '~') : h.rating === 'missing' ? c('dim', '-') : c('red', '!');
      console.log(`    ${icon} ${h.name}: ${h.detail}`);
    }
    if (result.security.reportEndpoints?.length) {
      console.log(`    ${c('cyan', '◆')} Report collectors (CSP/NEL): ${result.security.reportEndpoints.join(', ')}`);
    }
    if (result.security.formProviders.length) {
      console.log(`    ${c('cyan', '◆')} Form/booking providers (CSP): ${result.security.formProviders.join(', ')}`);
    }
    if (result.exposedIdentifiers?.length) {
      const list = result.exposedIdentifiers.map((i) => `${i.value} (${i.source})`).join(', ');
      console.log(`    ${c('yellow', '◆')} Exposed identifiers: email ${list}`);
    }
  }

  // SEO
  if (result.seo) {
    const headline = seoHeadline(result.seo);
    const color = result.seo.score === null ? 'dim' : headline.includes('(partial)') ? 'yellow' : scoreColor(result.seo.score);
    const noindexNote = result.seo.skipped?.length
      ? ` ${c('dim', '— noindex: canonical/hreflang/JSON-LD not scored')}`
      : '';
    console.log(`  ${c(color, headline)}${noindexNote}`);
    for (const check of result.seo.checks) {
      const icon = check.rating === 'good' ? c('green', '+') : check.rating === 'warning' ? c('yellow', '~') : check.rating === 'missing' ? c('dim', '-') : c('red', '!');
      console.log(`    ${icon} ${check.name}: ${check.detail}`);
    }
  }

  // Technology detection
  if (result.tech && result.tech.technologies.length > 0) {
    console.log(c('bold', '  Technology'));
    for (const t of result.tech.technologies) {
      const conf = t.confidence >= 90 ? '' : c('dim', ` (${t.confidence}%)`);
      console.log(`    ${t.name}${conf} — ${c('dim', t.evidence)}`);
    }
  }

  // Content classification
  if (result.content) {
    const cls = result.content;
    const label = cls.isAdult ? c('red', 'ADULT') : c('green', 'CLEAN');
    console.log(c('bold', '  Content Classification'));
    console.log(`    Rating: ${label} (score: ${cls.adultScore})`);

    if (cls.signals.length > 0) {
      console.log(`    Signals (${cls.signals.length}):`);
      for (const s of cls.signals.slice(0, 10)) {
        const col = severityColor(s.severity);
        console.log(`      ${c(col, `[${s.severity}]`)} ${s.value} — ${s.location}`);
      }
      if (cls.signals.length > 10) {
        console.log(`      ... and ${cls.signals.length - 10} more`);
      }
    }

    if (cls.affiliateLinks.length > 0) {
      console.log(`    Affiliate links (${cls.affiliateLinks.length}):`);
      for (const a of cls.affiliateLinks.slice(0, 5)) {
        const adultTag = a.isAdult ? c('red', ' [ADULT]') : '';
        console.log(`      ${a.network ?? 'unknown'}: ${a.url.slice(0, 70)}${adultTag}`);
      }
    }

    if (cls.adNetworks.length > 0) {
      console.log(`    Ad networks (${cls.adNetworks.length}):`);
      for (const a of cls.adNetworks) {
        const adultTag = a.isAdult ? c('red', ' [ADULT]') : '';
        console.log(`      ${a.name}${adultTag}`);
      }
    }
  }

  // Per-page audits (explicit --pages routes)
  if (result.pageAudits?.length) {
    console.log(c('bold', '  Page Audits'));
    for (const p of result.pageAudits) {
      if (!p.ok) {
        console.log(`    ${c('yellow', p.route)} — ${c('red', p.statusCode ? `HTTP ${p.statusCode}` : 'unreachable')}`);
        continue;
      }
      const seoStr = p.seoScore !== null ? c(scoreColor(p.seoScore), pageSeoLabel(p)) : 'SEO n/a';
      const noindexStr = p.isNoindex ? ` ${c('yellow', '[NOINDEX]')}` : '';
      console.log(`    ${c('cyan', p.route)} — ${seoStr}${noindexStr}`);
      if (p.title) console.log(`      Title: ${p.title.slice(0, 70)}`);
      if (p.htmlLang) console.log(`      Lang: ${p.htmlLang}`);
      if (p.canonicalUrl) console.log(`      Canonical: ${shortenUrl(p.canonicalUrl)}`);
      if (p.hreflang.length) {
        console.log(`      hreflang (${p.hreflang.length}): ${p.hreflang.map((h) => h.lang).join(', ')}`);
      } else {
        const hreflangCheck = p.seoIssues.find((ch) => ch.name === 'Hreflang');
        console.log(`      ${c('yellow', hreflangCheck ? `hreflang: ${hreflangCheck.detail}` : 'hreflang: none')}`);
      }
      if (p.formEndpoints.length) {
        console.log(`      Form endpoints: ${p.formEndpoints.map(shortenUrl).join(', ')}`);
      }
      // The failing checks are what makes "SEO 79/100" actionable — same
      // +/~/- list the root scan prints, but only the misses.
      for (const check of p.seoIssues ?? []) {
        const icon = check.rating === 'warning' ? c('yellow', '~') : check.rating === 'missing' ? c('dim', '-') : c('red', '!');
        console.log(`      ${icon} ${check.name}: ${check.detail}`);
      }
    }
  }

  // Errors
  if (result.errors.length > 0) {
    console.log(c('bold', '  Errors'));
    for (const e of result.errors) {
      console.log(`    ${c('yellow', e.scanner)}: ${e.error}`);
    }
  }

  console.log('');
}

function formatRobotsSummary(sum: RobotsTxtSummary | undefined): string {
  if (!sum) return '';
  const parts: string[] = [];
  if (sum.blocksAll) parts.push(c('yellow', 'Disallow / (all agents)'));
  else if (sum.blockedAgents.length) parts.push(`blocks: ${sum.blockedAgents.slice(0, 5).join(', ')}${sum.blockedAgents.length > 5 ? ` +${sum.blockedAgents.length - 5}` : ''}`);
  if (sum.disallowPaths.length) parts.push(`${sum.disallowPaths.length} disallow path(s): ${sum.disallowPaths.slice(0, 4).join(' ')}${sum.disallowPaths.length > 4 ? ' …' : ''}`);
  return parts.length ? ` — ${parts.join('; ')}` : '';
}

function formatSecurityTxtSummary(sum: SecurityTxtSummary | undefined): string {
  if (!sum) return '';
  const parts: string[] = [];
  if (sum.contacts.length) parts.push(`Contact ${sum.contacts.slice(0, 2).join(', ')}`);
  if (sum.expires) {
    const d = sum.expiresInDays;
    let tag = '';
    if (d === null) tag = c('yellow', 'unparseable');
    else if (d < 0) tag = c('red', `expired ${Math.abs(d)}d ago`);
    else if (d > 366) tag = c('yellow', `${d}d — RFC 9116 recommends <1y`);
    else tag = c('green', `${d}d, ok`);
    parts.push(`Expires ${sum.expires.slice(0, 10)} (${tag})`);
  } else {
    parts.push(c('yellow', 'no Expires (required by RFC 9116)'));
  }
  if (sum.hasSignature) parts.push('PGP-signed');
  return ` — ${parts.join(', ')}`;
}

function shortenUrl(url: string): string {
  try {
    const u = new URL(url, 'https://placeholder.test');
    // For same-domain paths, show path only
    if (u.hostname === 'placeholder.test') return u.pathname;
    // For external URLs, show host + path (truncated)
    const full = `${u.hostname}${u.pathname}`;
    return full.length > 60 ? full.slice(0, 57) + '...' : full;
  } catch {
    return url.length > 60 ? url.slice(0, 57) + '...' : url;
  }
}

