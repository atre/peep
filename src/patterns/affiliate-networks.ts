// Known affiliate network domains + redirect patterns
// Used to detect affiliate links and classify them as clean or adult

export interface AffiliatePattern {
  name: string;
  patterns: RegExp[];
  isAdult: boolean;
}

export const AFFILIATE_NETWORKS: AffiliatePattern[] = [
  // ── Adult affiliate networks ──
  {
    name: 'CrakRevenue',
    patterns: [/crakrevenue\.com/i, /crfrm\.com/i, /craktrax\.com/i],
    isAdult: true,
  },
  {
    name: 'Stripcash',
    patterns: [/stripcash\.com/i, /stripst\.com/i],
    isAdult: true,
  },
  {
    name: 'BongaCash',
    patterns: [/bongacash\.com/i, /bngpt\.com/i],
    isAdult: true,
  },
  {
    name: 'Chaturbate Affiliates',
    patterns: [/chaturbate\.com\/in\//i, /chaturbate\.com\/affiliates/i],
    isAdult: true,
  },
  {
    name: 'AWEmpire',
    patterns: [/awempire\.com/i, /awentw\.com/i],
    isAdult: true,
  },
  {
    name: 'ModelCentro',
    patterns: [/modelcentro\.com/i],
    isAdult: true,
  },
  {
    name: 'CamSoda Affiliates',
    patterns: [/camsoda\.com\/\?.*ref/i, /camsoda\.com\/affiliates/i],
    isAdult: true,
  },
  {
    name: 'Pornhub Affiliates',
    patterns: [/pornhub\.com\/\?.*ref/i, /modelhub\.com.*ref/i],
    isAdult: true,
  },
  {
    name: 'Flirt4Free',
    patterns: [/flirt4free\.com/i, /vsservers\.com/i],
    isAdult: true,
  },
  {
    name: 'XLoveCash',
    patterns: [/xlovecash\.com/i],
    isAdult: true,
  },
  {
    name: 'TubeTraffic',
    patterns: [/tubetraffic\.com/i],
    isAdult: true,
  },

  // ── Clean affiliate networks ──
  {
    name: 'Amazon Associates',
    patterns: [/amazon\.[a-z.]+\/.*[?&]tag=/i, /amzn\.to\//i, /amazon\.[a-z.]+\/dp\//i],
    isAdult: false,
  },
  {
    name: 'Impact',
    patterns: [/impact\.com/i, /impactradius\.com/i, /sjv\.io/i, /evyy\.net/i],
    isAdult: false,
  },
  {
    name: 'ShareASale',
    patterns: [/shareasale\.com/i],
    isAdult: false,
  },
  {
    name: 'CJ Affiliate',
    patterns: [/cj\.com/i, /commission-junction\.com/i, /dpbolvw\.net/i, /jdoqocy\.com/i, /tkqlhce\.com/i, /anrdoezrs\.net/i, /kqzyfj\.com/i],
    isAdult: false,
  },
  {
    name: 'Awin',
    patterns: [/awin1\.com/i, /awin\.com/i, /zenaps\.com/i],
    isAdult: false,
  },
  {
    name: 'Rakuten',
    patterns: [/rakuten\.com/i, /linksynergy\.com/i],
    isAdult: false,
  },
  {
    name: 'PartnerStack',
    patterns: [/partnerstack\.com/i, /partnerstackapi\.com/i],
    isAdult: false,
  },
  {
    name: 'NordVPN',
    patterns: [/nordvpn\.com.*[?&](?:ref|aff|utm_)/i, /go\.nordvpn\.net/i],
    isAdult: false,
  },
  {
    name: 'Surfshark',
    patterns: [/surfshark\.com.*[?&](?:ref|aff)/i, /get\.surfshark\.net/i],
    isAdult: false,
  },
  {
    name: 'ExpressVPN',
    patterns: [/expressvpn\.com.*[?&](?:ref|aff|offer)/i],
    isAdult: false,
  },
  {
    name: 'Coursera',
    patterns: [/coursera\.org.*[?&](?:ref|utm_)/i, /imp\.i384100\.net/i],
    isAdult: false,
  },
  {
    name: 'Refersion',
    patterns: [/refersion\.com/i],
    isAdult: false,
  },
  {
    name: 'ClickBank',
    patterns: [/clickbank\.net/i, /hop\.clickbank\.net/i],
    isAdult: false,
  },
  {
    name: 'FlexOffers',
    patterns: [/flexoffers\.com/i, /track\.flexlinkspro\.com/i],
    isAdult: false,
  },
];

// Internal redirect patterns (site's own affiliate redirects)
export const INTERNAL_REDIRECT_PATTERNS = [
  /\/go\//i,
  /\/out\//i,
  /\/refer\//i,
  /\/link\//i,
  /\/redirect\//i,
  /\/aff\//i,
  /\/partner\//i,
  /[?&]ref=/i,
  /[?&]aff_id=/i,
  /[?&]affiliate=/i,
];
