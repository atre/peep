import type { CliArgs } from './types.js';

const COMMANDS = ['scan', 'fleet', 'correlate', 'classify', 'report', 'diff', 'check', 'help', 'version'] as const;

export function parseArgs(argv: string[]): CliArgs {
  const args = argv.slice(2);
  const command = args[0] && !args[0].startsWith('-') ? args[0] : 'help';
  const domains: string[] = [];
  const flags: Record<string, string | boolean> = {};

  let i = 1;
  while (i < args.length) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const eqIdx = key.indexOf('=');
      if (eqIdx !== -1) {
        flags[key.slice(0, eqIdx)] = key.slice(eqIdx + 1);
      } else if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
        // Peek: if next arg looks like a value, use it
        const next = args[i + 1];
        if (next && !COMMANDS.includes(next as any) && !next.includes('.')) {
          flags[key] = next;
          i++;
        } else if (next && next.includes('.') && key !== 'format' && key !== 'out' && key !== 'only' && key !== 'config' && key !== 'pages' && key !== 'dns') {
          // Looks like a domain, not a flag value
          flags[key] = true;
        } else {
          flags[key] = args[i + 1];
          i++;
        }
      } else {
        flags[key] = true;
      }
    } else if (arg.startsWith('-') && arg.length === 2) {
      // Short flags
      const shortMap: Record<string, string> = {
        f: 'format',
        o: 'out',
        c: 'config',
        j: 'json',
        q: 'quiet',
        v: 'verbose',
      };
      const key = shortMap[arg[1]] ?? arg[1];
      if (key === 'json') {
        flags.format = 'json';
      } else if (i + 1 < args.length && !args[i + 1].startsWith('-')) {
        flags[key] = args[i + 1];
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      // Positional — treat as domain
      domains.push(arg);
    }
    i++;
  }

  return { command, domains, flags };
}

export function printHelp(): void {
  console.log(`
peep — Fleet OPSEC scanner

Fingerprint detection, grey-red classification, and cross-site correlation
for a fleet of domains. Detects shared analytics IDs, favicon hashes,
TLS SAN overlap, WHOIS registrant matches, and more.

USAGE
  peep <command> [domains...] [flags]

COMMANDS
  scan <domain...>        Scan one or more domains (full fingerprint report)
  fleet                   Scan all domains in .peeprc fleet config
  correlate [domain...]   Scan fleet + compute cross-site correlation matrix
                          (accepts domains as args, or uses .peeprc fleet config)
  classify [domain...]    Grey-red content classification (fleet if no args)
  report                  Full fleet audit — scan + correlate + write report
  diff <fileA> <fileB>    Compare two scan/report JSON outputs
  check <domain>          Deploy-gate check (exit 0=pass, 1=fail)
  version                 Print version
  help                    Show this help

SCANNERS
  dns        A/AAAA/MX/TXT/NS/CNAME records
  http       Status, headers, timing, redirects, cookies
  tls        Certificate issuer, SAN, protocol, cipher, expiry
  whois      Registrar, registrant, dates (+ RDAP fallback)
  html       Title, meta/OG/Twitter card tags, JSON-LD/structured data,
             structure hashes, comments, form/booking endpoints
  analytics  GA4, GTM, AdSense, Umami, Clarity, Plausible, Hotjar, etc.
  assets     Favicon hash, CSS/JS hashes, fonts (including CSS @font-face),
             images (img + SVG + background-image)
  robots     robots.txt, ads.txt, security.txt, humans.txt, sitemaps,
             sitemap content hash
  content    Adult keyword scoring, affiliate/ad network detection
  security   Security headers score (HSTS, CSP, X-Frame-Options, etc.),
             CORS wildcard, HTML comments OPSEC, CSP script allowlist
  tech       Stack detection (Next.js, WordPress, Tailwind, Cloudflare,
             NEL, etc.)

DERIVED SCORES (selectable via --only)
  security   Security-header score (a real scanner; also shown in reports)
  seo        SEO score derived from html + robots. Selecting --only seo runs
             those source scanners and the derivation. Under a partial --only,
             checks whose source scanner didn't run are reported as
             "not evaluated", never as failing.

FLAGS
  --format, -f <fmt>     Output format: text or json (default: text)
  -j                     Shorthand for --format json
  --out, -o <file>       Write output to file (scan/classify: always JSON;
                          correlate/report: .json → JSON, else text report)
  --config, -c <path>    Custom .peeprc config path
  --only <scanners>      Comma-separated scanner list to run
  --skip-whois           Skip WHOIS lookups (slow)
  --skip-assets          Skip asset fetching (favicon/CSS/JS downloads)
  --hash-content         Fetch and hash CSS/JS file content (on by default)
  --skip-content-hash    Skip CSS/JS content hashing (URL-only fingerprinting)
  --pages <n|routes>     Number: fetch top N sitemap pages (merges form endpoints).
                          Routes: comma-separated paths (e.g. /de,/fr) get a per-page
                          SEO/hreflang audit — use for i18n routes a homepage scan misses.
  -v                     Verbose output (show scanner timing, raw data,
                          and hash values in correlation findings)
  -q                     Quiet output (suppress per-domain lines, show summary only)
  --cluster <name>       Cluster context for check command (clean|adult)
  --min-score <n>        Minimum security score for check command (default: 50)
  --require-security-txt Fail check if security.txt is absent
  --expect <state>       check only: --expect noindex (alias: --prelaunch)
                          converts a noindex failure into a PASS annotated
                          "noindex (declared pre-launch)" — for a site that's
                          public for a payment-provider review but
                          deliberately kept noindex until go-live. Must be
                          passed explicitly every time — never a .peeprc
                          default — so it can't mask a forgotten noindex
                          after launch.
  --dns <server>          Pin DNS resolution to this server (e.g. 1.1.1.1)
                          instead of the OS resolver. Without it, the OS
                          resolver's result still wins — but if it returns
                          NXDOMAIN while <server> (default 1.1.1.1) resolves
                          fine, peep warns instead of a bare ENOTFOUND
                          (stale negative-cache signature after a fresh
                          cutover). Applies to every scanner — dns's own
                          queries plus the fetch()/tls.connect() fallback.

EXIT CODES
  0  All clear
  1  Warnings — isolation score below correlationWarning threshold
  2  Critical — shared tracking IDs, cross-cluster violations

CONFIG (.peeprc)
  Searched in order: --config path, ./.peeprc, ./.peeprc.json, ~/.peeprc

  {
    "fleet": {
      "domains": ["a.com", "b.com"],
      "clusters": {
        "clean-1": ["a.com"],
        "adult": ["b.com"]
      }
    },
    "thresholds": {
      "adultScore": 30,
      "correlationWarning": 40,
      "correlationCritical": 70
    },
    "scanning": {
      "concurrency": 5,
      "timeout": 15000,
      "whoisEnabled": true
    }
  }

  Cluster names starting with "adult" are treated as adult clusters.
  Cross-cluster violations (adult signals on clean sites) trigger exit 2.

  scanning.only limits which scanners run fleet-wide (e.g. ["html", "assets", "analytics"]).
  scanning.hashContent (default: true) fetches CSS/JS content for deeper fingerprinting.

EXAMPLES
  peep scan example.com
  peep scan https://example.com --only dns,tls,http
  peep scan example.com --only seo        # derived score: runs html + robots
  peep scan example.com another.com --format json
  peep fleet --skip-whois
  peep fleet -q
  peep correlate
  peep correlate a.com b.com c.com
  peep correlate -j
  peep correlate -v
  peep classify --format json
  peep report --out audit.json
  peep diff audit-2026-01.json audit-2026-02.json
  peep check example.com --cluster clean
  peep check example.com --min-score 70
  peep scan example.com --pages 5
  peep scan example.com --pages /de,/fr     # per-page SEO/hreflang audit
  peep check example.com --require-security-txt
  peep check example.com --cluster clean --expect noindex   # pre-launch gate
  peep check example.com --cluster clean --prelaunch        # same, shorthand
  peep scan example.com --dns 1.1.1.1   # bypass a stale OS negative-cache entry
`);
}

export function printVersion(): void {
  console.log('peep 0.1.0');
}
