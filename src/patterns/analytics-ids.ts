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
      /googletagmanager\.com[^<>]{0,200}?[?&]id=(GTM-[A-Z0-9]{4,8})/g,
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
      /umami\.(?:is|cloud)[^<>]{0,200}?website-id=['"]([0-9a-f-]{36})['"]/g,
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
      /plausible\.io\/js\/[^<>]{0,200}?data-domain=['"]([^'"]+)['"]/g,
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
      /connect\.facebook\.net[^<>]{0,200}?\/(\d{15,16})\//g,
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
      /hotjar\.com[^<>]{0,200}?(\d{6,8})/g,
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
      /exoclick\.com[^<>]{0,200}?zone(?:_id)?[=:]\s*['"]?(\d+)/gi,
      /idzone\s*=\s*['"]?(\d+)/g,
    ],
    type: 'ads',
  },
  {
    name: 'JuicyAds Spot',
    patterns: [
      /juicyads\.com[^<>]{0,200}?spot[=:]\s*['"]?(\d+)/gi,
    ],
    type: 'ads',
  },
  {
    name: 'Google Ads Conversion',
    patterns: [
      /['"](?:AW-)(\d{9,11})['"]/g,
      /googleadservices\.com\/pagead\/conversion\/(\d{9,11})\//g,
    ],
    type: 'ads',
  },
  {
    name: 'Bing UET Tag',
    patterns: [
      /bat\.bing\.com[\s\S]{0,300}?\bti\s*:\s*['"]?(\d{6,10})/g,
      /\bti\s*:\s*['"]?(\d{6,10})['"]?[\s\S]{0,300}?bat\.bing\.com/g,
    ],
    type: 'ads',
  },

  // ── Social / marketing pixels (account-level IDs) ──
  {
    name: 'TikTok Pixel',
    patterns: [
      /ttq\.load\(['"]([A-Z0-9]{15,25})['"]/g,
      /analytics\.tiktok\.com\/i18n\/pixel\/events\.js\?sdkid=([A-Z0-9]{15,25})/g,
    ],
    type: 'social',
  },
  {
    name: 'LinkedIn Insight',
    patterns: [
      /_linkedin_partner_id\s*=\s*['"](\d{4,10})['"]/g,
      /px\.ads\.linkedin\.com\/collect\/?\?pid=(\d{4,10})/g,
    ],
    type: 'social',
  },
  {
    name: 'Pinterest Tag',
    patterns: [
      /pintrk\(['"]load['"],\s*['"](\d{10,16})['"]/g,
    ],
    type: 'social',
  },
  {
    name: 'Snap Pixel',
    patterns: [
      /snaptr\(['"]init['"],\s*['"]([0-9a-f-]{36})['"]/g,
    ],
    type: 'social',
  },
  {
    name: 'X/Twitter Pixel',
    patterns: [
      /twq\(['"](?:config|init)['"],\s*['"]([a-z0-9]{5,8})['"]/g,
    ],
    type: 'social',
  },
  {
    name: 'Reddit Pixel',
    patterns: [
      /rdt\(['"]init['"],\s*['"](t2_[a-z0-9]{4,12})['"]/g,
    ],
    type: 'social',
  },
  {
    name: 'Yandex Metrika',
    patterns: [
      /\bym\((\d{6,10}),\s*['"]init['"]/g,
      /mc\.yandex\.ru\/watch\/(\d{6,10})/g,
    ],
    type: 'analytics',
  },

  // ── Product analytics / error tracking (project- or org-level keys) ──
  {
    name: 'Segment Write Key',
    patterns: [
      /analytics\.load\(['"]([A-Za-z0-9]{20,40})['"]\)/g,
      /cdn\.segment\.com\/analytics\.js\/v1\/([A-Za-z0-9]{20,40})\//g,
    ],
    type: 'analytics',
  },
  {
    name: 'Mixpanel Token',
    patterns: [
      /mixpanel\.init\(['"]([a-f0-9]{32})['"]/g,
    ],
    type: 'analytics',
  },
  {
    name: 'Amplitude API Key',
    patterns: [
      /amplitude\.(?:getInstance\(\)\.)?init\(['"]([a-f0-9]{32})['"]/g,
    ],
    type: 'analytics',
  },
  {
    name: 'PostHog Key',
    patterns: [
      /posthog\.init\(['"](phc_[A-Za-z0-9]{20,60})['"]/g,
    ],
    type: 'analytics',
  },
  {
    name: 'Sentry Org',
    patterns: [
      /https:\/\/[a-f0-9]{16,40}@(o\d{3,12})\.ingest(?:\.[a-z]{2})?\.sentry\.io\/\d+/g,
    ],
    type: 'other',
  },
  {
    name: 'Sentry DSN',
    patterns: [
      /https:\/\/([a-f0-9]{16,40})@[a-z0-9.-]*sentry\.io\/\d+/g,
    ],
    type: 'other',
  },
  {
    name: 'OneSignal App',
    patterns: [
      /OneSignal\.init\(\{[^}]{0,200}?appId\s*:\s*['"]([0-9a-f-]{36})['"]/g,
      /onesignal\.com\/sdks\/[^"'<>]{0,200}?appId=([0-9a-f-]{36})/g,
    ],
    type: 'other',
  },

  // ── Payments / commerce (account-level — the strongest ownership signals) ──
  {
    name: 'Stripe Publishable Key',
    patterns: [
      /(?<![A-Za-z0-9_])(pk_(?:live|test)_[A-Za-z0-9]{20,120})(?![A-Za-z0-9_])/g,
    ],
    type: 'other',
  },
  {
    name: 'PayPal Client ID',
    patterns: [
      /paypal\.com\/sdk\/js\?[^"'<>]{0,300}?client-id=([A-Za-z0-9_-]{40,100})/g,
    ],
    type: 'other',
  },
  {
    name: 'Shopify Store',
    patterns: [
      /cdn\.shopify\.com\/s\/files\/1\/(\d{4}\/\d{4}(?:\/\d{4})?)\//g,
      /Shopify\.shop\s*=\s*['"]([a-z0-9-]+\.myshopify\.com)['"]/g,
    ],
    type: 'other',
  },
  {
    name: 'Klaviyo Company',
    patterns: [
      /klaviyo\.com\/onsite\/js\/(?:klaviyo\.js)?\?[^"'<>]{0,100}?company_id=([A-Za-z0-9]{6})/g,
      /static\.klaviyo\.com\/onsite\/js\/([A-Za-z0-9]{6})\/klaviyo\.js/g,
    ],
    type: 'other',
  },
  {
    name: 'Mailchimp Account',
    patterns: [
      /list-manage\.com\/subscribe\/post(?:-json)?\?[^"'<>]{0,200}?\bu=([a-f0-9]{20,32})/g,
    ],
    type: 'other',
  },
  {
    name: 'Trustpilot Business Unit',
    patterns: [
      /data-businessunit-id=['"]([a-f0-9]{24})['"]/g,
    ],
    type: 'other',
  },

  // ── Support / chat widgets (workspace-level IDs) ──
  {
    name: 'Intercom App',
    patterns: [
      /widget\.intercom\.io\/widget\/([a-z0-9]{6,12})/g,
      /Intercom\(['"]boot['"],\s*\{[^}]{0,300}?app_id\s*:\s*['"]([a-z0-9]{6,12})['"]/g,
      /intercomSettings\s*=\s*\{[^}]{0,300}?app_id\s*:\s*['"]([a-z0-9]{6,12})['"]/g,
    ],
    type: 'other',
  },
  {
    name: 'Crisp Website',
    patterns: [
      /CRISP_WEBSITE_ID\s*=\s*['"]([0-9a-f-]{36})['"]/g,
    ],
    type: 'other',
  },
  {
    name: 'Tawk.to Property',
    patterns: [
      /embed\.tawk\.to\/([a-f0-9]{24})\b/g,
    ],
    type: 'other',
  },
  {
    name: 'HubSpot Portal',
    patterns: [
      /js(?:-[a-z0-9]+)?\.hs-scripts\.com\/(\d{5,10})\.js/g,
      /js(?:-[a-z0-9]+)?\.hsforms\.net\/forms\/[^"'<>]{0,200}?portalId=(\d{5,10})/g,
      /hbspt\.forms\.create\(\{[^}]{0,300}?portalId\s*:\s*['"]?(\d{5,10})/g,
    ],
    type: 'other',
  },
  {
    name: 'Cookiebot',
    patterns: [
      /data-cbid=['"]([0-9a-f-]{36})['"]/g,
    ],
    type: 'other',
  },
  {
    name: 'Disqus Shortname',
    patterns: [
      /https?:\/\/([a-z0-9-]{2,60})\.disqus\.com\/embed\.js/g,
    ],
    type: 'other',
  },

  // ── Site builders / infra keys ──
  {
    name: 'Webflow Site',
    patterns: [
      /data-wf-site=['"]([a-f0-9]{24})['"]/g,
    ],
    type: 'other',
  },
  {
    name: 'Firebase Project',
    patterns: [
      /https?:\/\/([a-z0-9-]{4,60})\.firebaseapp\.com/g,
      /https?:\/\/([a-z0-9-]{4,60})\.firebaseio\.com/g,
    ],
    type: 'other',
  },
  {
    name: 'Google API Key',
    patterns: [
      /(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])/g,
    ],
    type: 'other',
  },
  {
    name: 'reCAPTCHA Site Key',
    patterns: [
      /(?<![A-Za-z0-9_-])(6L[A-Za-z0-9_-]{38})(?![A-Za-z0-9_-])/g,
    ],
    type: 'other',
  },
  {
    name: 'hCaptcha Site Key',
    patterns: [
      /h-captcha[^<>]{0,200}?data-sitekey=['"]([0-9a-f-]{36})['"]/g,
      /data-sitekey=['"]([0-9a-f-]{36})['"][^<>]{0,200}?h-captcha/g,
    ],
    type: 'other',
  },
  {
    name: 'Cloudflare Turnstile Site Key',
    patterns: [
      /['"](0x4AAAAAAA[A-Za-z0-9_-]{8,24})['"]/g,
    ],
    type: 'other',
  },
  {
    name: 'Adobe Launch',
    patterns: [
      /assets\.adobedtm\.com\/([a-f0-9]{20,40})\//g,
    ],
    type: 'other',
  },
];

// DNS-based verification records that link domains to accounts
export const DNS_VERIFICATION_PATTERNS = [
  { name: 'Google Workspace', pattern: /google-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Facebook Domain', pattern: /facebook-domain-verification=([a-z0-9]+)/ },
  { name: 'Bing Webmaster', pattern: /msvalidate\.01=([A-F0-9]+)/i },
  { name: 'Yandex Webmaster', pattern: /yandex-verification:\s*([a-f0-9]+)/i },
  { name: 'Adobe Domain', pattern: /adobe-idp-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Atlassian Domain', pattern: /atlassian-domain-verification=([A-Za-z0-9+/=_-]+)/ },
  { name: 'Mailchimp DKIM', pattern: /k=rsa;[\s\S]{0,500}?dkim\._domainkey/ },
  { name: 'Apple Business', pattern: /apple-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Stripe', pattern: /stripe-verification=([A-Za-z0-9_-]+)/ },
  { name: 'DocuSign', pattern: /docusign=([A-Za-z0-9-]+)/ },
  { name: 'GlobalSign', pattern: /_globalsign-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'OpenAI', pattern: /openai-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Notion', pattern: /notion-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Miro', pattern: /miro-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Canva', pattern: /canva-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Dropbox', pattern: /dropbox-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Zoho', pattern: /zoho-verification=([A-Za-z0-9._-]+)/ },
  { name: 'MongoDB Atlas', pattern: /mongodb-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Have I Been Pwned', pattern: /have-i-been-pwned-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Postman', pattern: /postman-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Linear', pattern: /linear-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'HubSpot Developer', pattern: /hubspot-developer-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Cloudflare', pattern: /cloudflare-verify=([A-Za-z0-9_-]+)/ },
  { name: 'Keybase', pattern: /keybase-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Proton Mail', pattern: /protonmail-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Pinterest', pattern: /pinterest-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Brevo', pattern: /sendinblue-code:\s*([A-Za-z0-9_-]+)/i },
  { name: 'HackerOne', pattern: /h1-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Zapier', pattern: /zapier-domain-verification-challenge=([A-Za-z0-9_-]+)/ },
  { name: 'Twilio', pattern: /twilio-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Smartsheet', pattern: /smartsheet-site-validation=([A-Za-z0-9_-]+)/ },
  { name: 'LogMeIn', pattern: /logmein-verification-code=([A-Za-z0-9_-]+)/ },
  { name: 'Citrix', pattern: /citrix-verification-code=([A-Za-z0-9_-]+)/ },
  { name: 'KnowBe4', pattern: /knowbe4-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Atlassian Statuspage', pattern: /status-page-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Docker', pattern: /docker-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Amazon SES', pattern: /^amazonses:\s*([A-Za-z0-9+/=_-]+)/i },
  { name: 'Brave Creators', pattern: /brave-ledger-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Workplace (Meta)', pattern: /workplace-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Autodesk', pattern: /autodesk-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Sophos', pattern: /sophos-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Calendly', pattern: /calendly-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Shopify', pattern: /shopify-verification-code=([A-Za-z0-9_-]+)/ },
  { name: 'Loom', pattern: /loom-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Jamf', pattern: /jamf-site-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Krisp', pattern: /krisp-domain-verification=([A-Za-z0-9_-]+)/ },
  { name: 'Anthropic', pattern: /anthropic-domain-verification-[a-z0-9]+=([A-Za-z0-9_-]+)/ },
  { name: 'Tailscale', pattern: /^TAILSCALE-([A-Za-z0-9_-]+)/i },
  { name: 'Webex', pattern: /webexdomainverification\.?[A-Za-z0-9]*=([A-Za-z0-9_-]+)/i },
];
