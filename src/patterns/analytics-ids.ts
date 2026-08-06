// Analytics and tracking ID extraction patterns
// Used to detect shared tracking across fleet domains (major fingerprint signal)

export interface AnalyticsExtractor {
  name: string;
  patterns: RegExp[];
  type: 'analytics' | 'ads' | 'social' | 'other';
}

export const ANALYTICS_EXTRACTORS: AnalyticsExtractor[] = [
  // ── Google ──
  {
    name: 'GA4 Measurement ID',
    patterns: [
      /['"]G-([A-Z0-9]{6,12})['"]/g,
      /gtag\(['"]config['"],\s*['"]G-([A-Z0-9]{6,12})['"]/g,
      /measurementId['":\s]+['"]G-([A-Z0-9]{6,12})['"]/g,
    ],
    type: 'analytics',
  },
  {
    name: 'GTM Container',
    patterns: [
      /GTM-([A-Z0-9]{4,8})/g,
      /googletagmanager\.com.*[?&]id=(GTM-[A-Z0-9]{4,8})/g,
    ],
    type: 'analytics',
  },
  {
    name: 'Google AdSense Publisher',
    patterns: [
      /ca-pub-(\d{10,16})/g,
      /data-ad-client=['"]ca-pub-(\d{10,16})['"]/g,
      /google_ad_client\s*=\s*['"]ca-pub-(\d{10,16})['"]/g,
    ],
    type: 'ads',
  },
  {
    name: 'Google Site Verification',
    patterns: [
      /google-site-verification['"]\s*content=['"]([^'"]+)['"]/g,
    ],
    type: 'other',
  },

  // ── Self-hosted analytics ──
  {
    name: 'Umami Website ID',
    patterns: [
      /data-website-id=['"]([0-9a-f-]{36})['"]/g,
      /umami\.(?:is|cloud).*?website-id=['"]([0-9a-f-]{36})['"]/g,
    ],
    type: 'analytics',
  },
  {
    name: 'Umami Script Source',
    patterns: [
      /src=['"]([^'"]*umami[^'"]*\.js)['"]/g,
    ],
    type: 'analytics',
  },
  {
    name: 'Plausible Domain',
    patterns: [
      /plausible\.io\/js\/.*?data-domain=['"]([^'"]+)['"]/g,
      /src=['"]([^'"]*plausible[^'"]*\.js)['"]/g,
    ],
    type: 'analytics',
  },
  {
    name: 'Matomo Site ID',
    patterns: [
      /setSiteId['"(,\s]+['"]?(\d+)['"]?/g,
      /idsite=(\d+)/g,
    ],
    type: 'analytics',
  },

  // ── Social/marketing pixels ──
  {
    name: 'Facebook Pixel',
    patterns: [
      /fbq\(['"]init['"],\s*['"](\d{15,16})['"]/g,
      /connect\.facebook\.net.*?\/(\d{15,16})\//g,
    ],
    type: 'social',
  },
  {
    name: 'Microsoft Clarity',
    patterns: [
      /clarity\.ms\/tag\/([a-z0-9]+)/gi,
    ],
    type: 'analytics',
  },
  {
    name: 'Hotjar',
    patterns: [
      /hotjar\.com.*?(\d{6,8})/g,
      /hjid['":\s]+(\d{6,8})/g,
    ],
    type: 'analytics',
  },

  // ── CDN analytics ──
  {
    name: 'Cloudflare Web Analytics',
    patterns: [
      /data-cf-beacon=['"]\{[^}]*"token"\s*:\s*"([a-f0-9]{32})"[^}]*\}['"]/g,
      // HTML-entity-encoded variant: browsers render data-cf-beacon="{&#34;token&#34;:&#34;abc123&#34;}"
      /data-cf-beacon=['"]?\{[^}]*&#34;token&#34;\s*:\s*&#34;([a-f0-9]{32})&#34;[^}]*\}['"]?/g,
      /(cloudflareinsights\.com\/beacon[^'"]*)['"]/g,
    ],
    type: 'analytics',
  },

  // ── Ad platform IDs ──
  {
    name: 'ExoClick Zone',
    patterns: [
      /exoclick\.com.*?zone(?:_id)?[=:]\s*['"]?(\d+)/gi,
      /idzone\s*=\s*['"]?(\d+)/g,
    ],
    type: 'ads',
  },
  {
    name: 'JuicyAds Spot',
    patterns: [
      /juicyads\.com.*?spot[=:]\s*['"]?(\d+)/gi,
    ],
    type: 'ads',
  },
];

// DNS-based verification records that link domains to accounts
export const DNS_VERIFICATION_PATTERNS = [
  { name: 'Google Workspace', pattern: /google-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Facebook Domain', pattern: /facebook-domain-verification=([a-z0-9]+)/ },
  { name: 'Bing Webmaster', pattern: /msvalidate\.01=([A-F0-9]+)/i },
  { name: 'Yandex Webmaster', pattern: /yandex-verification:\s*([a-f0-9]+)/i },
  { name: 'Adobe Domain', pattern: /adobe-idp-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Atlassian Domain', pattern: /atlassian-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Mailchimp DKIM', pattern: /k=rsa;.*?dkim\._domainkey/ },
];
