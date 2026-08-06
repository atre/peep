// Ad network detection patterns — script sources and known domains
// Classified as clean or adult for cross-cluster leak detection

export interface AdNetworkPattern {
  name: string;
  patterns: RegExp[];
  isAdult: boolean;
}

export const AD_NETWORKS: AdNetworkPattern[] = [
  // ── Adult ad networks ──
  {
    name: 'ExoClick',
    patterns: [/exoclick\.com/i, /exosrv\.com/i, /exdynsrv\.com/i, /a\.exosrv\.com/i],
    isAdult: true,
  },
  {
    name: 'TrafficJunky',
    patterns: [/trafficjunky\.com/i, /trafficjunky\.net/i],
    isAdult: true,
  },
  {
    name: 'JuicyAds',
    patterns: [/juicyads\.com/i, /juicyads\.net/i, /js\.juicyads\.com/i],
    isAdult: true,
  },
  {
    name: 'TrafficStars',
    patterns: [/trafficstars\.com/i, /tsyndicate\.com/i],
    isAdult: true,
  },
  {
    name: 'ClickAdu',
    patterns: [/clickadu\.com/i, /clickadilla\.com/i],
    isAdult: true,
  },
  {
    name: 'PopAds',
    patterns: [/popads\.net/i, /serve\.popads\.net/i],
    isAdult: true,
  },
  {
    name: 'Adsterra',
    patterns: [/adsterra\.com/i, /betaadvertising\.com/i, /adstera\.com/i],
    isAdult: true,
  },
  {
    name: 'PropellerAds',
    patterns: [/propellerads\.com/i, /propelllerads\.com/i, /propellerclick\.com/i],
    isAdult: true,
  },
  {
    name: 'HilltopAds',
    patterns: [/hilltopads\.com/i, /hilltopads\.net/i],
    isAdult: true,
  },
  {
    name: 'EroAdvertising',
    patterns: [/eroadvertising\.com/i, /ero-advertising\.com/i],
    isAdult: true,
  },
  {
    name: 'TrafficFactory',
    patterns: [/trafficfactory\.biz/i, /trafficfactory\.com/i],
    isAdult: true,
  },

  // ── Clean ad networks ──
  {
    name: 'Google AdSense',
    patterns: [/pagead2\.googlesyndication\.com/i, /adsbygoogle/i, /googleads\.g\.doubleclick\.net/i],
    isAdult: false,
  },
  {
    name: 'Google Ad Manager',
    patterns: [/securepubads\.g\.doubleclick\.net/i, /googletag/i],
    isAdult: false,
  },
  {
    name: 'Mediavine',
    patterns: [/mediavine\.com/i, /scripts\.mediavine\.com/i],
    isAdult: false,
  },
  {
    name: 'Raptive (AdThrive)',
    patterns: [/raptive\.com/i, /adthrive\.com/i, /ads\.adthrive\.com/i],
    isAdult: false,
  },
  {
    name: 'Ezoic',
    patterns: [/ezoic\.com/i, /ezoic\.net/i, /ezojs\.com/i],
    isAdult: false,
  },
  {
    name: 'Carbon Ads',
    patterns: [/carbonads\.com/i, /cdn\.carbonads\.com/i, /srv\.carbonads\.net/i],
    isAdult: false,
  },
  {
    name: 'BuySellAds',
    patterns: [/buysellads\.com/i, /bsacdn\.com/i],
    isAdult: false,
  },
  {
    name: 'Amazon Publisher Services',
    patterns: [/amazon-adsystem\.com/i, /aax\.amazon/i],
    isAdult: false,
  },
  {
    name: 'ProPush.me',
    patterns: [/propush\.me/i, /p\.propush\.me/i, /notix\.io/i],
    isAdult: false, // can be used on either, but script itself is clean
  },
  {
    name: 'Monetag',
    patterns: [/monetag\.com/i, /monetag\.io/i],
    isAdult: false,
  },
];

// Push notification services (grey area — used in sweepstakes/CPA funnels)
export const PUSH_NETWORKS: AdNetworkPattern[] = [
  { name: 'ProPush', patterns: [/propush\.me/i], isAdult: false },
  { name: 'RollerAds', patterns: [/rollerads\.com/i], isAdult: false },
  { name: 'Pushground', patterns: [/pushground\.com/i], isAdult: false },
  { name: 'RichPush', patterns: [/richpush\.co/i], isAdult: false },
  { name: 'DatsPush', patterns: [/datspush\.com/i], isAdult: false },
  { name: 'Megapu.sh', patterns: [/megapu\.sh/i, /megapush\.com/i], isAdult: false },
];
