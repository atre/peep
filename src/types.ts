// ── Scanner Results ──

export interface DnsResult {
  a: string[];
  aaaa: string[];
  mx: Array<{ exchange: string; priority: number }>;
  txt: string[];
  ns: string[];
  cname: string[];
  googleVerification: string | null;
  microsoftVerification: string | null;
  facebookVerification: string | null;
  /** Parsed `v=spf1` record from the apex TXT set (null = no SPF published).
   *  Optional: absent in JSON written before 0.2. */
  spf?: SpfRecord | null;
  /** Parsed `_dmarc.<domain>` TXT (null = no DMARC published). */
  dmarc?: DmarcRecord | null;
  /** CAA records as `tag value` strings, e.g. `issue letsencrypt.org`. */
  caa?: string[];
  /** DKIM TXT records found at common selectors (`google._domainkey.<domain>`
   *  etc.) — informational, not exhaustive (a sender's actual selector may not
   *  be in the probed list). Optional: absent in JSON written before 0.2. */
  dkim?: Array<{ selector: string; raw: string }>;
}

export interface SpfRecord {
  raw: string;
  includes: string[];
  ip4: string[];
  ip6: string[];
  /** `redirect=` modifier target, if any. */
  redirect: string | null;
  /** Terminal `all` qualifier: `-all` (fail), `~all` (softfail), `?all` (neutral),
   *  `+all` (pass — effectively no SPF), or null when the record has no `all`. */
  all: '-all' | '~all' | '?all' | '+all' | null;
}

export interface DmarcRecord {
  raw: string;
  /** `p=` policy: none | quarantine | reject (null when malformed). */
  policy: string | null;
  /** `sp=` subdomain policy. */
  subdomainPolicy: string | null;
  /** Aggregate report addresses (`rua=`), `mailto:` prefix stripped. */
  rua: string[];
  /** Forensic report addresses (`ruf=`), `mailto:` prefix stripped. */
  ruf: string[];
  pct: number | null;
}

export interface HttpResult {
  statusCode: number;
  headers: Record<string, string>;
  serverHeader: string | null;
  poweredBy: string | null;
  contentType: string | null;
  timing: number;
  redirectChain: string[];
  setCookies: string[];
  xRobotsTag: string | null;
  /** URL the final (post-redirect, post-fallback) response came from — its scheme
   *  is the truth for "served over HTTPS", not the scheme we started with. */
  finalUrl: string | null;
  /** Accept-Language header actually sent, or null when none was sent (the
   *  default — matches Googlebot, avoids skewing locale-default sites). */
  acceptLanguage: string | null;
}

export interface TlsResult {
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  san: string[];
  protocol: string;
  cipher: string;
  fingerprint: string;
  daysUntilExpiry: number | null;
}

export interface WhoisResult {
  registrar: string | null;
  createdDate: string | null;
  updatedDate: string | null;
  expiryDate: string | null;
  nameservers: string[];
  registrantOrg: string | null;
  registrantCountry: string | null;
  dnssec: string | null;
  raw: string;
  /** Days until `expiryDate` (negative = expired), null when unparseable or
   *  absent. Optional: absent in JSON written before this field existed. */
  expiresIn?: number | null;
}

export interface JsonLdData {
  type: string | null;
  name: string | null;
  url: string | null;
  sameAs: string[];
}

export interface HtmlResult {
  title: string | null;
  metaGenerator: string | null;
  metaViewport: string | null;
  metaRating: string | null;
  metaDescription: string | null;
  metaRobots: string | null;
  ogTags: Record<string, string>;
  twitterCards: Record<string, string>;
  canonicalUrl: string | null;
  scriptSources: string[];
  stylesheetSources: string[];
  htmlLang: string | null;
  headStructureHash: string;
  bodyStructureHash: string;
  inlineScriptHashes: string[];
  inlineStyleHashes: string[];
  comments: string[];
  jsonLd: JsonLdData[];
  formEndpoints: string[];
  /** Email addresses found via mailto: links or bare text in the page — capped at 20. */
  emails: string[];
}

export interface AnalyticsResult {
  ga4: string[];
  gtm: string[];
  adsense: string[];
  umami: Array<{ websiteId: string; src: string }>;
  facebook: string[];
  clarity: string[];
  plausible: string[];
  cloudflare: string[];
  other: Array<{ name: string; id: string }>;
}

export interface AssetResult {
  faviconHash: string | null;
  faviconUrl: string | null;
  cssHashes: Array<{ url: string; hash: string }>;
  jsHashes: Array<{ url: string; hash: string }>;
  fontFamilies: string[];
  fontSources: string[];
  imageCount: number;
  ogImages: string[];
}

export interface RobotsResult {
  robotsTxt: string | null;
  robotsTxtHash: string | null;
  sitemapUrls: string[];
  sitemapHash: string | null;
  affiliateRedirectPaths: string[];
  adsTxt: string | null;
  adsTxtHash: string | null;
  adsTxtPubIds: string[];
  securityTxt: string | null;
  humansTxt: string | null;
  /** Parsed key facts so the text report can say what the files contain
   *  instead of just "present" (present since 0.2 — absent in older JSON). */
  robotsSummary?: RobotsTxtSummary;
  securityTxtSummary?: SecurityTxtSummary;
  humansTxtSummary?: HumansTxtSummary;
}

export interface HumansTxtSummary {
  lines: number;
  contact: string | null;
  team: string | null;
}

export interface RobotsTxtSummary {
  /** Agents (`User-agent:` values) that have `Disallow: /` — i.e. are blocked entirely. */
  blockedAgents: string[];
  /** True when `*` is fully disallowed (site closed to all crawlers). */
  blocksAll: boolean;
  /** Distinct Disallow paths (excluding the bare `/`). */
  disallowPaths: string[];
  /** Number of `User-agent:` groups. */
  agentCount: number;
}

export interface SecurityTxtSummary {
  contacts: string[];
  /** Raw `Expires:` value. */
  expires: string | null;
  /** Days until `Expires:` (negative = expired), null when unparseable. */
  expiresInDays: number | null;
  policy: string | null;
  hasSignature: boolean;
}

export interface ContentSignal {
  type: 'keyword' | 'affiliate' | 'ad_network' | 'meta_rating' | 'rta_label' | 'link' | 'image_alt' | 'domain_name';
  value: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  location: string;
  /** Score multiplier for repeated hits (1 = single mention). Defaults to 1 when absent. */
  weight?: number;
}

export interface DetectedAffiliate {
  url: string;
  network: string | null;
  isAdult: boolean;
  anchorText: string | null;
}

export interface DetectedAd {
  name: string;
  scriptSrc: string;
  isAdult: boolean;
}

export interface ContentClassification {
  isAdult: boolean;
  adultScore: number;
  signals: ContentSignal[];
  affiliateLinks: DetectedAffiliate[];
  adNetworks: DetectedAd[];
  contentRating: string | null;
}

// ── Security Headers ──

export interface SecurityHeader {
  name: string;
  present: boolean;
  value: string | null;
  rating: 'good' | 'warning' | 'missing' | 'bad';
  detail: string;
}

export interface SecurityResult {
  score: number;
  headers: SecurityHeader[];
  /**
   * Form/booking provider hosts (calendly.com, formspree.io, …) declared in the
   * homepage CSP. Captured here because it's a fleet-correlation signal available
   * without crawling subpages — see correlation `shared-form-provider`.
   */
  formProviders: string[];
  /**
   * Violation-report collectors declared in CSP `report-uri`, the `Report-To`
   * / `Reporting-Endpoints` headers (also used by NEL). Normalized to
   * `host/path` without query. A `<account>.report-uri.com` or Sentry ingest
   * endpoint shared by two sites is the same account — see correlation
   * `shared-report-endpoint`. Optional: absent in JSON written before 0.2.
   */
  reportEndpoints?: string[];
}

// ── SEO ──

export interface SeoCheck {
  name: string;
  present: boolean;
  value: string | null;
  rating: 'good' | 'warning' | 'missing' | 'bad';
  detail: string;
}

export interface SeoResult {
  /**
   * Null when neither source scanner (html, robots) produced a result — e.g.
   * the HTTP fetch that both depend on failed. A derived score with nothing
   * to derive from must read as "not evaluated", never as a false 0.
   */
  score: number | null;
  checks: SeoCheck[];
  /** Number of checks actually evaluated (length of `checks`). */
  evaluated: number;
  /** Number of checks a full scan would evaluate — when `evaluated < total` the
   *  score is partial (e.g. a robots-only `--only` run) and must not be quoted
   *  as a plain "/100". */
  total: number;
  /** Check names deliberately not evaluated because the page is noindex
   *  (Canonical URL / Hreflang / Structured Data don't apply), or because the
   *  page is a legal/utility route where a given check doesn't apply (e.g.
   *  Structured Data on /privacy). */
  skipped?: string[];
  /** Check name → human-readable reason, for entries in `skipped` whose reason
   *  isn't already self-evident from context (the noindex skip is explained
   *  elsewhere by callers; this covers newer skip reasons like route-based
   *  ones). Additive and optional — absent when nothing needs explaining. */
  skipReasons?: Record<string, string>;
}

// ── Technology Detection ──

export interface TechDetection {
  name: string;
  category: 'framework' | 'server' | 'cdn' | 'cms' | 'hosting' | 'language' | 'other';
  confidence: number;
  evidence: string;
}

export interface TechResult {
  technologies: TechDetection[];
}

// ── Scan Result ──

export interface ScanResult {
  domain: string;
  url: string;
  timestamp: string;
  duration: number;
  isNoindex: boolean;
  dns: DnsResult | null;
  http: HttpResult | null;
  tls: TlsResult | null;
  whois: WhoisResult | null;
  html: HtmlResult | null;
  analytics: AnalyticsResult | null;
  assets: AssetResult | null;
  robots: RobotsResult | null;
  content: ContentClassification | null;
  security: SecurityResult | null;
  seo: SeoResult | null;
  tech: TechResult | null;
  errors: Array<{ scanner: string; error: string }>;
  /** Per-page audits, populated only when `--pages` is given explicit routes. */
  pageAudits?: PageAudit[];
  /** Email addresses exposed anywhere (DMARC rua/ruf, CAA iodef, security.txt,
   *  mailto:/body text), for the OPSEC line and cross-site correlation. */
  exposedIdentifiers?: Array<{ kind: 'email'; value: string; source: string }>;
  /** Non-good security/SEO/email-auth checks in pulse's fleet-wide Finding
   *  shape — additive, for tools that fold peep in as site findings. */
  findings?: Finding[];
}

/**
 * Fleet-wide finding shape — the reference contract is pulse's `src/types.ts`
 * (`id`, `scope`, `severity`, `title`, `detail?`, `hint?`). `scope` is fixed
 * at `'site'` (pulse's `Scope` union has no per-category values — `seo:`/
 * `sec:`/`email:` are reserved `id` prefixes there, not scope values), so a
 * peep-sourced finding type-checks cleanly wherever pulse's Finding does.
 */
export interface Finding {
  id: string;
  scope: 'site';
  severity: 'crit' | 'warn';
  title: string;
  detail?: string;
  /** Where to look — `peep scan <domain> --only security|seo|dns`. */
  hint?: string;
}

export interface HreflangAlternate {
  lang: string;
  href: string;
}

/** SEO/i18n audit of one explicit route (e.g. /de), distinct from the homepage. */
export interface PageAudit {
  /** Route as requested on the CLI (e.g. "/de"). */
  route: string;
  /** Resolved absolute URL that was fetched. */
  url: string;
  statusCode: number | null;
  ok: boolean;
  title: string | null;
  htmlLang: string | null;
  canonicalUrl: string | null;
  isNoindex: boolean;
  hreflang: HreflangAlternate[];
  seoScore: number | null;
  /** SEO checks that did not rate `good` on this page — the reason behind
   *  `seoScore`, so a "79/100" is actionable and diffable across deploys. */
  seoIssues: SeoCheck[];
  formEndpoints: string[];
  /** Number of SEO checks actually evaluated on this page (mirrors
   *  `SeoResult.evaluated`) — lets `seoScore`'s denominator be shown as
   *  "N/total pass" instead of just the raw score. Optional: absent in JSON
   *  written before this field existed. */
  seoEvaluated?: number;
}

// ── Correlation ──

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface CorrelationFinding {
  type: string;
  severity: Severity;
  domains: string[];
  detail: string;
  evidence: string;
}

export interface CorrelationReport {
  timestamp: string;
  domains: string[];
  /** Domains whose HTTP fetch failed or returned an error status — their
   *  content-level signals (HTML, analytics, assets, security) were never
   *  observed, so an isolation score over them is only DNS/TLS/WHOIS-deep.
   *  Optional for backwards-compatible JSON. */
  unreachable?: Array<{ domain: string; reason: string }>;
  findings: CorrelationFinding[];
  score: number;
  matrix: Record<string, Record<string, number>>;
  summary: { critical: number; high: number; medium: number; low: number };
}

// ── Config ──

export interface PeepConfig {
  fleet: FleetConfig;
  thresholds: ThresholdConfig;
  scanning: ScanningConfig;
}

export interface FleetConfig {
  domains: string[];
  clusters: Record<string, string[]>;
}

export interface ThresholdConfig {
  adultScore: number;
  correlationWarning: number;
  correlationCritical: number;
}

export interface ScanningConfig {
  concurrency: number;
  timeout: number;
  userAgent: string;
  followRedirects: boolean;
  whoisEnabled: boolean;
  /** When true, fetch and hash CSS/JS file content (not just URLs) for deeper template fingerprinting */
  hashContent: boolean;
  /** Scanner whitelist — only run these scanners (equivalent to --only on CLI) */
  only?: string[];
  /** URL scheme for all scanner fetches. 'http' only when the user explicitly
   *  scanned an http:// target (LAN/staging) — fleet/default scans stay https. */
  scheme?: 'https' | 'http';
  /** --dns <server>: pin DNS resolution (dns scanner's own queries, plus the
   *  cross-check every fetch()/tls.connect() call falls back to when the OS
   *  resolver returns NXDOMAIN) to this server instead of 1.1.1.1. Unset means
   *  "system default" — resolution behavior is otherwise unchanged. */
  dnsServer?: string;
  /** --lang <xx>: Accept-Language header value to send. Unset (default) sends
   *  no Accept-Language at all — matches Googlebot and avoids skewing a
   *  locale-default site (e.g. a DE-default store) toward its EN variant. */
  acceptLanguage?: string;
  /** --host <domain>: hostname presented as TLS SNI and the HTTP Host header,
   *  while the scan still connects to the literal target URL/domain — lets a
   *  preview URL (pr-123.vercel.app) be scanned as if it were the real
   *  production domain. Independent of `scheme` — usable on a normal https
   *  scan, not just the explicit http:// local-target case. */
  hostOverride?: string;
}

// ── Diff ──

export interface DiffEntry {
  type: 'new_finding' | 'resolved_finding' | 'new_domain' | 'removed_domain' | 'analytics_change' | 'noindex_change' | 'adult_score_change' | 'score_change' | 'page_change';
  domain?: string;
  detail: string;
  severity?: Severity;
}

export interface DiffReport {
  fileA: string;
  fileB: string;
  timestamp: string;
  changes: DiffEntry[];
  summary: { added: number; removed: number; changed: number };
  /** How many semantic fields buildDiff actually compared, and which volatile
   *  fields (timestamps, timing, per-build hashes) it deliberately ignored —
   *  so "0 change(s)" reads as "compared and clean", not "compared nothing". */
  compared?: { fields: number; ignored: string[] };
}

// ── Check ──

export interface CheckResult {
  domain: string;
  passed: boolean;
  failures: string[];
  /**
   * Non-failing annotations — e.g. a noindex that would normally fail the gate
   * but was explicitly declared pre-launch via --expect noindex/--prelaunch.
   * Never affects `passed`; exists so a converted-to-PASS check is still visible
   * instead of silently disappearing.
   */
  notes: string[];
  scanResult: ScanResult;
}

// ── CLI ──

export interface CliArgs {
  command: string;
  domains: string[];
  flags: Record<string, string | boolean>;
}

export type OutputFormat = 'text' | 'json' | 'table';
