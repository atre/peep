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
}

export interface ContentSignal {
  type: 'keyword' | 'affiliate' | 'ad_network' | 'meta_rating' | 'rta_label' | 'link' | 'image_alt';
  value: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  location: string;
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
  formEndpoints: string[];
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
}

// ── Diff ──

export interface DiffEntry {
  type: 'new_finding' | 'resolved_finding' | 'new_domain' | 'removed_domain' | 'analytics_change' | 'noindex_change' | 'adult_score_change';
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
