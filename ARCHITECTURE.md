# peep — Architecture

## Overview

```
                                          ┌────────────────┐
                                     ┌───>│  Text report   │  human-readable
┌──────────────┐   ┌──────────────┐  │    └────────────────┘
│  CLI (args)  │──>│   Scanner    │──┤    ┌────────────────┐
│  peep <cmd>  │   │ orchestrator │  ├───>│  JSON (-j)     │  CI / peep diff
└──────┬───────┘   └──────┬───────┘  │    └────────────────┘
       │                  │          │    ┌────────────────┐
┌──────┴───────┐   ┌──────┴───────┐  └───>│  Exit code     │  0 / 1 / 2 gate
│   .peeprc    │   │ Correlation  │       └────────────────┘
│ fleet+config │   │   matrix     │
└──────────────┘   └──────────────┘
```

Every command funnels through one scanner orchestrator (`src/scanners/index.ts`),
which fans out per domain under a concurrency limit. Correlation runs afterward
over the collected `ScanResult[]` — it never issues requests of its own.

## Scanner phases

Phases exist because later scanners consume earlier output rather than re-fetching.
The HTTP scanner returns the response body, and phases 2 and 3 reuse it.

```
Phase 1  (parallel, network)      dns · http · tls · whois · robots
                │
                ├─ html body ──>  Phase 2   html · analytics · assets · content
                │
                └─ headers ────>  Phase 3   security · tech
                                      │
                                      └──>  Derived   seo (from html + robots)
```

A failing scanner degrades to `null` for its slice of the result rather than
aborting the domain — a WHOIS timeout must not lose the TLS findings.

## Project structure

```
peep/
├── src/
│   ├── index.ts              # Entry point — command routing, DNS override install
│   ├── cli.ts                # Arg parsing, --help, --version
│   ├── config.ts             # .peeprc discovery, defaults, normalization
│   ├── resolver.ts           # Process-wide dns.lookup() override (see below)
│   ├── concurrency.ts        # Semaphore + mapConcurrent + rate limiting
│   ├── utils.ts              # Hashing, colors, cluster helpers, output files
│   ├── types.ts              # Shared result types for every scanner
│   ├── scanners/
│   │   ├── index.ts          # Orchestrator — phase ordering, per-scanner isolation
│   │   ├── dns.ts            # A/AAAA/MX/TXT/NS/CNAME/CAA, SPF + DMARC parsing
│   │   ├── http.ts           # Status, headers, timing, redirect chain, cookies
│   │   ├── tls.ts            # Issuer, SAN list, protocol, cipher, expiry
│   │   ├── whois.ts          # Registrar/registrant, RDAP fallback
│   │   ├── robots.ts         # robots.txt, ads.txt, security.txt, sitemaps
│   │   ├── html.ts           # Meta/OG/Twitter, JSON-LD, structure hashes, forms
│   │   ├── analytics.ts      # GA4, GTM, pixels, 40+ vendor account IDs, subpage merge
│   │   ├── assets.ts         # Favicon/CSS/JS hashes, fonts, images
│   │   ├── content.ts        # Grey-red scoring, affiliate + ad network detection
│   │   ├── security.ts       # Security-header score, CSP analysis, CORS, report collectors
│   │   ├── tech.ts           # Framework/CDN/host/server fingerprinting
│   │   └── seo.ts            # Derived SEO score over html + robots
│   ├── correlation/
│   │   ├── matrix.ts         # Pairwise + fleet-wide finding generation
│   │   └── scoring.ts        # Isolation score, report assembly, formatting
│   ├── commands/
│   │   ├── scan.ts           # One or more explicit domains
│   │   ├── fleet.ts          # Every domain in .peeprc
│   │   ├── correlate.ts      # fleet + correlation matrix
│   │   ├── classify.ts       # Grey-red classification only
│   │   ├── report.ts         # Full audit written to a file
│   │   ├── diff.ts           # Compare two JSON snapshots
│   │   └── check.ts          # Deploy gate (exit 0/1)
│   └── patterns/             # Keyword + network lists (append-only)
│       ├── adult-keywords.ts
│       ├── affiliate-networks.ts
│       ├── ad-networks.ts
│       └── analytics-ids.ts
├── test/                     # node --test, 18 files
├── .github/workflows/ci.yml
├── CLAUDE.md                 # AI assistant project instructions
├── ARCHITECTURE.md           # This file
└── README.md
```

**33 source files, ~6,600 lines, 291 tests.**

## Data flow

```
parseArgs(argv)
 │
 ├─ loadConfig()            .peeprc → --config → ./.peeprc → ./.peeprc.json → ~/.peeprc
 ├─ installDnsOverride()    patches dns.lookup() process-wide, before any fetch
 │
 └─ command dispatch
     │
     ├─ scan <domains>  ─┐
     ├─ fleet           ─┤
     ├─ classify        ─┼─> mapConcurrent(domains, concurrency, scanDomain)
     ├─ correlate       ─┤        │
     ├─ report          ─┘        └─> phase 1 ─> phase 2 ─> phase 3 ─> derived
     │                                                  │
     │                                                  v
     ├─ correlate/report ──> computeCorrelation(results, clusters)
     │                          │
     │                          ├─ pairwise findings   (per domain pair)
     │                          ├─ fleet-wide findings (shared IDs, leaks)
     │                          └─ buildReport() ─> isolation score 0-100
     │
     ├─ diff <a> <b>   ──> compare two JSON snapshots, no network
     └─ check <domain> ──> single scan ─> pass/fail gate
```

## Correlation model

Findings carry a severity (`critical` / `high` / `medium` / `low`) and are either
**pairwise** (a signal shared between two specific domains) or **fleet-wide**
(a tracking ID on 3+ sites, a cross-cluster content leak, a DMARC mailbox or
SPF `include:` that names another fleet domain).

Vendor IDs from `analytics.other` are classed in `matrix.ts`: account-level
keys (Stripe, PayPal, ad pixels, Sentry DSN, …) are `critical` when shared,
workspace/site keys (Intercom, reCAPTCHA, HubSpot, …) are `high`, and
site-local counters (Matomo `idsite`) are ignored. `DNS:*` entries are TXT
tokens already covered by `shared-dns-txt`.

Two adjustments keep the score meaningful on real fleets:

- **Same-cluster downgrade** — infrastructure sharing (MX, DOM structure, CSS,
  favicon) between domains in the same cluster is expected, so it drops in
  severity. Cross-cluster sharing of the same signal stays at full weight.
- **Commodity discounting** — signals shared by "any Cloudflare + Astro site"
  (nameservers, popular webfonts, generic headers) are weighted low, so
  unrelated brands on the same stack don't read as linked.

The isolation score normalizes pairwise penalties by `ceil(C(n,2)/3)` so a large
fleet doesn't auto-zero from expected overlap, while fleet-wide penalties apply
at full weight. See the README's Correlation section for the formula.

## DNS resolution

`fetch()` and `tls.connect()` use the OS resolver (`dns.lookup()`), while the
`dns` scanner queries nameservers directly (`dns.resolve4`). Those can disagree
right after a domain cutover — a stale negative-cache entry makes a live domain
throw `ENOTFOUND` in `http`/`tls` while `dns` scans clean.

`src/resolver.ts` patches `dns.lookup()` process-wide so every scanner resolves
through one decision: OS success is used as-is; OS failure is cross-checked
against a public resolver, and the disagreement is either reported in the error
message (default) or overridden (`--dns <server>`). See the README's DNS
Resolution section.

## Untrusted input boundary

`src/fetch-guard.ts` exists because peep deliberately fetches from domains it
does not control, and a scanned page chooses its own subresource URLs.

The boundary is drawn at **who chose the URL**, not at what it points to:

| URL origin | Trust | Rule |
|---|---|---|
| The scan target (user-supplied) | Trusted | Fetched as-is — `peep scan http://localhost:3000` must work |
| Harvested from scanned HTML | Untrusted | Must resolve to a public address, or match the target's own host |

`isFetchAllowed()` rejects non-HTTP schemes, private/loopback/link-local/CGNAT
ranges, and hostnames where *any* resolved address is private (a name resolving
to both public and private space is a rebinding attempt). IPv6 is fully
expanded before checking, since `new URL()` rewrites `[::ffff:127.0.0.1]` to
`::ffff:7f00:1`.

`readCapped()`/`readCappedBuffer()` bound every response body, because
`AbortSignal.timeout` limits time rather than bytes — a target streaming
quickly can exhaust memory well inside the timeout.

## Constraints

- **Zero runtime dependencies.** Node built-ins and global `fetch` only. This is
  a hard constraint — new features must be built without adding a dependency.
- **ESM only**, Node ≥ 20.
- Scanner results must conform to the types in `src/types.ts`.
- Pattern lists are append-only — don't restructure existing entries.
