# peep

[![CI](https://github.com/atre/peep/actions/workflows/ci.yml/badge.svg)](https://github.com/atre/peep/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Fleet OPSEC scanner — fingerprint detection, grey-red classification, and cross-site correlation.

Scans a fleet of domains for signals that could reveal common ownership: shared analytics IDs, favicon hashes, TLS SAN overlap, WHOIS registrant matches, DNS patterns, HTML structure fingerprints, and more. Classifies sites as adult ("red") or clean ("grey") and flags cross-cluster violations.

**Zero runtime dependencies. One command. Exit codes built for CI.**

```bash
peep correlate          # Scan the fleet, score how linkable it is
```

## Features

- **11 scanners across 3 phases** — DNS, HTTP, TLS, WHOIS, robots, HTML, analytics, assets, content, security headers, tech stack
- **Third-party account IDs** — 40+ vendor keys (Stripe, PayPal, Meta/TikTok/LinkedIn pixels, Sentry, reCAPTCHA, Intercom, HubSpot, Shopify, …) plus 50+ DNS TXT verification tokens; a shared key is a shared account
- **Email OPSEC** — SPF / DMARC / CAA parsed and judged (spoofable? report mailbox shared with another site?), with `check --require-email-auth`
- **Cross-site correlation** — pairwise similarity matrix plus a fleet-wide isolation score (0-100)
- **Grey-red classification** — weighted adult-content scoring with cross-cluster leak detection
- **Commodity-signal discounting** — "any Cloudflare + Astro site" signals are weighted down, so unrelated brands on the same stack don't read as linked
- **Deploy gate** — `peep check` returns exit 0/1 for CI, with a `--prelaunch` escape hatch
- **Snapshot diffing** — `peep diff` tracks new/resolved findings and analytics drift between audits
- **Derived SEO + security scores** — honest `null` instead of a fabricated 0 when a fetch fails
- **DNS split-brain detection** — catches stale OS negative-cache entries that make a live domain look dead
- **Zero runtime dependencies** — Node built-ins and global `fetch` only

## Requirements

- Node.js >= 20
- `whois` CLI binary (for WHOIS lookups; optional — RDAP fallback used when unavailable)

No runtime npm dependencies. Uses only Node.js built-ins and the global `fetch` API.

## Install

Install straight from GitHub (not published to npm):

```bash
npm install -g github:atre/peep
```

Or from source:

```bash
git clone https://github.com/atre/peep.git
cd peep
npm install
npm run build
npm link        # makes `peep` available globally
```

### mise-managed Node / non-interactive shells

If Node is installed via [mise](https://mise.jdx.dev/) (or asdf, nvm, etc.),
`npm link` installs the `peep` binary under that tool's shim/bin directory —
fine in an interactive shell where the activation hook has run, but **a
non-interactive shell (CI, a cron job, an automation/agent session) often
doesn't source `.zshrc`/`.bashrc`, so PATH never picks up mise's dirs and
`peep` resolves to "not found"** even though `npm link` succeeded.

Fixes, in order of preference:

```bash
# 1. Run mise's activation explicitly for that shell/script
eval "$(mise activate bash)"   # or: zsh, fish, ...
peep scan example.com

# 2. Or run through mise directly, no activation needed
mise exec node -- peep scan example.com

# 3. Fallback that always works, no PATH/link required at all
node ~/git/peep/dist/index.js scan example.com
```

Option 3 is the reliable one for scripts/automation that can't assume any
particular shell setup — alias it if you use it often:

```bash
alias peep='node ~/git/peep/dist/index.js'
```

Or run directly without linking at all:

```bash
node dist/index.js <command> [args]
```

## Quick start

```bash
# Scan a single domain (https:// prefix stripped automatically)
peep scan example.com
peep scan https://example.com

# Scan multiple domains, output JSON
peep scan example.com another.com -j

# Run only specific scanners
peep scan example.com --only dns,tls,http

# Scan all fleet domains from .peeprc
peep fleet

# Cross-site correlation analysis
peep correlate

# Grey-red content classification
peep classify

# Full audit report to file
peep report --out audit.json

# Compare two audit snapshots
peep diff audit-jan.json audit-feb.json

# Deploy-gate check (exit 0 = ready, exit 1 = blocked)
peep check example.com --cluster clean
```

## Commands

| Command | Description |
|---|---|
| `scan <domain...>` | Scan one or more domains (full fingerprint report) |
| `fleet` | Scan all domains listed in `.peeprc` fleet config |
| `correlate` | Fleet scan + pairwise cross-site correlation matrix |
| `classify [domain...]` | Grey-red content classification only (defaults to fleet) |
| `report` | Full fleet audit — scan + correlate + write report file |
| `diff <fileA> <fileB>` | Compare two JSON scan/report outputs — new/resolved findings, domain changes, analytics drift |
| `check <domain>` | Deploy-gate check — verifies the site answers, noindex removed, no adult on clean cluster, security score >= threshold, optional per-route SEO gates (`--pages`, `--min-seo`, `--require-seo`) |
| `version` | Print version |
| `help` | Show help |

## Flags

| Flag | Short | Description |
|---|---|---|
| `--format <text\|json>` | `-f` | Output format (default: `text`) |
| | `-j` | Shorthand for `--format json` |
| `--out <file>` | `-o` | Write output to file. `scan`/`classify` always write JSON; `correlate`/`report` write JSON for a `.json` path, otherwise the text report |
| `--config <path>` | `-c` | Custom `.peeprc` config path |
| `--only <scanners>` | | Comma-separated list of scanners to run (also accepts derived `seo`). Works on `scan`, `fleet` and `check`; an explicit `whois` here overrides `scanning.whoisEnabled: false`. Under a partial run the SEO headline is marked `partial — n/12 checks evaluated` |
| `--skip-whois` | | Skip WHOIS lookups |
| `--skip-assets` | | Skip asset fetching (favicon/CSS/JS downloads) |
| `--hash-content` | | Fetch and hash CSS/JS file content (deeper template fingerprinting; on by default) |
| `--skip-content-hash` | | Skip CSS/JS content hashing — fingerprint by URL only (overrides the default) |
| `--pages <n\|routes>` | | Number: fetch top N sitemap pages, following one level of sitemap index (catches form/booking endpoints on subpages). Routes: comma-separated paths (e.g. `/de,/fr`) get a per-page SEO/hreflang audit (score plus the failing checks under each route, also in JSON as `pageAudits[].seoIssues`) — for i18n routes a homepage scan can't reach. Works on `scan`, `report` and `check` (where each route becomes a gate) |
| | `-v` | Verbose output (scanner timing + raw data sections) |
| | `-q` | Quiet output (suppress per-domain lines, show summary only) |
| `--brief` | | Red-only output for gates/hooks: ≤ 10 lines per domain — missing/bad checks, HTTP errors, NOINDEX, scan errors; no good/warning lines. Implies `-q`. Works on `scan`, `check`, `fleet` |
| `--lang <xx>` | | Send `Accept-Language: <xx>` on every fetch (incl. `--pages`). Default sends **no** `Accept-Language` at all (matches Googlebot) — a hardcoded `en-US` would audit a DE-default store's EN variant. The header actually sent is printed under `HTTP` |
| `--fleet <path>` | | Read `domains` / `pages` from a `fleet.yaml` (default `./fleet.yaml` if present) — schema shared with looksy/texter/trusty: `domains: [...]`, `pages: [...]`, `locales: [...]`, `viewports: [...]`; peep uses only `domains` + `pages`. An explicit `.peeprc` domains list and an explicit `--pages` always win |
| `--cluster <name>` | | Cluster context for `check` command (`clean` or `adult`) |
| `--min-score <n>` | | Minimum security score for `check` command (default: 50) |
| `--require-security-txt` | | Fail `check` if `security.txt` is absent |
| `--require-email-auth` | | Fail `check` unless SPF is published with a `-all`/`~all` terminal and DMARC with `p=quarantine\|reject` — a transactional-mail domain without them is spoofable and lands in spam |
| `--min-seo <n>` | | `check` only. Fail if the SEO score of the root page or any `--pages` route is below `n` |
| `--require-seo <checks>` | | `check` only. Comma-separated SEO check names that must rate *good* on the root page and every `--pages` route, e.g. `"Open Graph,Canonical URL"` |
| `--expect-hreflang <g>` | | `check` only. Comma-separated `glob:none` pairs, e.g. `/blog/*:none` — routes matching the glob (trailing `*` = prefix match) are deliberately untranslated and exempt from the Hreflang check under `--require-seo` / `--min-seo` |
| `--expect <state>` | | `check` only. `--expect noindex` (aliases `--prelaunch`, `--allow-noindex`, `--stage pre-launch`) converts a noindex failure into a PASS annotated `noindex (declared pre-launch)` — for a site that's public for a payment-provider review but deliberately kept noindex until go-live. Must be passed explicitly per invocation, never a `.peeprc` default, so it can't mask a forgotten noindex after launch |
| `--dns <server>` | | Pin DNS resolution to this server (e.g. `1.1.1.1`) instead of the OS resolver — see [DNS Resolution](#dns-resolution) |

## Scanners

Peep runs 11 scanners across three phases, plus two derived scores (`seo`, `security`) computed from earlier output:

**Phase 1** (parallel): `dns`, `http`, `tls`, `whois`, `robots`
**Phase 2** (needs HTML from phase 1): `html`, `analytics`, `assets`, `content`
**Phase 3** (needs headers from phase 1): `security`, `tech`
**Derived**: `seo` (scored from `html` + `robots`)

| Scanner | What it checks |
|---|---|
| `dns` | A, AAAA, MX, TXT, NS, CNAME, CAA records; Google/Bing/Facebook verification tokens; parsed SPF (`include:`, `ip4:`/`ip6:`, terminal `all`) and `_dmarc` (policy, `rua`/`ruf` mailboxes) with a spoofability verdict (`+ SPF: -all …` / `- DMARC: none — spoofed mail is still delivered`) |
| `http` | Status, headers, timing, full redirect chain (manual hop-by-hop, max 10), cookies, X-Robots-Tag |
| `tls` | Certificate issuer, SAN list, protocol, cipher, expiry |
| `whois` | Registrar, registrant org, creation/expiration dates (RDAP fallback for .dev, .app, etc.) |
| `html` | Title, meta/OG tags, Twitter card tags (`twitter:card`, `twitter:image`, etc.), JSON-LD structured data (`@type`, `name`, `sameAs` for cross-site correlation), canonical URL, structure hashes, inline script/style hashes, comments, form/booking endpoints (Formspree, Calendly, Typeform, Tally, etc.); `metaRobots` for noindex detection |
| `analytics` | GA4, GTM, AdSense, Google Ads conversion, Umami (websiteId), Facebook Pixel, Clarity, Plausible, Cloudflare Analytics, Hotjar, Matomo, ExoClick, JuicyAds; TikTok / LinkedIn / Pinterest / Snap / X / Reddit pixels, Bing UET, Yandex Metrika; Segment, Mixpanel, Amplitude, PostHog, Sentry (org + DSN key), OneSignal; Stripe publishable key, PayPal client id, Shopify store, Klaviyo, Mailchimp account, Trustpilot; Intercom, Crisp, Tawk.to, HubSpot portal, Cookiebot, Disqus; Webflow site, Firebase project, Google API key, reCAPTCHA / hCaptcha / Turnstile site keys, Adobe Launch. 50+ DNS TXT verification tokens (Google, Facebook, Apple, Stripe, DocuSign, Atlassian, Notion, OpenAI, HubSpot, Zoho, Calendly, Shopify, …) land as `DNS:<vendor>`. With `--pages`, IDs found on subpages (checkout, contact, booking) are merged in — that's where Stripe keys and captcha site keys live |
| `assets` | Favicon hash, CSS/JS file hashes (URL-based or content-based with `--hash-content`), font families/sources (including CSS `@font-face`), image count (`<img>` + inline `<svg>` + CSS `background-image`), OG/Twitter card images |
| `robots` | `robots.txt` (blocked agents, `Disallow /`, disallow paths) + affiliate redirect path detection (`/go/`, `/out/`, `/aff/`, etc.); `ads.txt` pub-id parsing; `security.txt` (contacts, `Expires` with RFC 9116 <1y check, PGP signature); `humans.txt`; sitemap URLs |
| `content` | Adult keyword scoring (configurable threshold), meta rating, RTA label, affiliate network detection (adult + clean), ad network detection |
| `security` | Security headers score (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP, security.txt, server version disclosure). Informational checks: CORS `Access-Control-Allow-Origin: *` wildcard, HTML comments OPSEC warning (framework markers such as React/Next `<!--$-->` hydration boundaries are ignored), CSP script allowlist cross-reference (scripts loaded from origins not in `script-src`). Also extracts form/booking providers declared in CSP (`calendly.com`, `formspree.io`, …) and violation-report collectors (CSP `report-uri`, `Report-To`, `Reporting-Endpoints` — e.g. `<account>.report-uri.com`, Sentry ingest) for fleet correlation |
| `tech` | Stack fingerprinting: frameworks (Next.js, Nuxt, Astro, Gatsby, Hugo, WordPress, etc.), CSS (Tailwind CSS via utility class analysis), CDNs (Cloudflare, Vercel, Netlify, AWS CloudFront), hosting (GitHub Pages, Cloudflare Pages — boosted by CNAME to `*.pages.dev`), servers (Nginx, Apache, Caddy), monitoring (NEL/Report-To network error logging) |
| `seo` *(derived)* | SEO score over `html` + `robots`: title, meta description, canonical, Open Graph, Twitter card, language, viewport, JSON-LD, robots.txt, sitemap, hreflang, HTTPS. Addressable via `--only seo` (runs its source scanners); checks whose source scanner didn't actually produce a result — not selected under a partial `--only`, *or* selected but its fetch failed — are reported as *not evaluated* rather than failing, and the score itself is `null` ("not evaluated") rather than a fabricated 0 or 100 when nothing at all was evaluated |

Use `--only` to run a subset: `peep scan example.com --only dns,tls,security`. Derived scores are selectable too — `peep scan example.com --only seo` runs `html` + `robots` and computes the score.

## DNS Resolution

`http` and `tls` resolve hostnames via `fetch()`/`tls.connect()`, which use the
OS resolver (`dns.lookup()` — getaddrinfo, with its own cache). The `dns`
scanner queries nameservers directly (`dns.resolve4`/etc, c-ares) and doesn't
go through that cache. Normally this is invisible — but right after a domain
is cut over (new nameservers, fresh DNS record), the OS resolver can still
hold a stale negative-cache entry while a direct query already resolves fine.
That split produced a real incident: `dns` scanned clean while `http`/`tls`
both threw `getaddrinfo ENOTFOUND` for the same, already-live domain.

Peep patches `dns.lookup()` process-wide (the one function `fetch()` and
`tls.connect()` both call internally — verified empirically, not just
documented behavior) so every scanner resolves through the same decision:

- **OS resolver succeeds** — used as-is, unchanged from stock Node.
- **OS resolver fails** (`ENOTFOUND`/`ENODATA`) — cross-checked against a
  public/configured resolver (`1.1.1.1` by default, or `--dns <server>`):
  - Disagreement + no `--dns` given (the default) — the OS failure still
    stands (nothing is silently overridden), but the error now reads e.g.
    `getaddrinfo ENOTFOUND example.com — local resolver returned NXDOMAIN but
    1.1.1.1 resolves (192.0.2.1) — likely stale negative cache; retry
    with --dns 1.1.1.1` instead of a bare `ENOTFOUND`.
  - Disagreement + `--dns <server>` given — the public answer is used and the
    scan proceeds normally.
  - Both resolvers agree there's nothing — the original error, untouched.

```bash
peep scan example.com                  # default: OS resolver wins, warns on disagreement
peep scan example.com --dns 1.1.1.1    # bypass a stale OS negative-cache entry
```

`--dns` also pins the `dns` scanner's own record queries to that server.

## Noindex / Staging Detection

Peep detects sites that are not yet indexable and marks them as `NOINDEX`. A site is flagged if:

- `<meta name="robots" content="noindex ...">` or `<meta name="googlebot" content="noindex ...">` is present in the HTML
- `X-Robots-Tag: noindex` response header is set

`NOINDEX` status is shown prominently in `scan`, `fleet`, and `report` output. The `check` command will fail if the site is still `NOINDEX`.

## Grey-red Classification

Classification is a **weighted signal score**, not a machine-learning classifier.
`content` collects signals from five sources:

| Source | Detail |
|---|---|
| Body text | 66 keyword patterns (`src/patterns/adult-keywords.ts`), each tagged with a severity and one of 12 categories, matched against de-tagged HTML |
| Domain name | The same patterns (excluding `low` severity) run against the hostname, so an adult domain with a clean landing page still scores |
| Image `alt` text | Same patterns, `low` severity skipped |
| Declared ratings | `<meta name="rating">` and the RTA label — both `critical` |
| Networks | Affiliate links and ad-network scripts flagged `isAdult` in the pattern lists — `critical` |

Each signal contributes by severity — `critical` 25, `high` 15, `medium` 5,
`low` 1 — multiplied by a repetition weight (1× for a single mention, 1.5× at
3+, 2× at 10+), summed, and capped at 100. A site is ADULT when the score meets
`thresholds.adultScore` (default 30).

A cluster whose name starts with `adult` (case-insensitive) is a red cluster.
Adult signals on a site in any other cluster — including one not assigned to a
cluster at all — raise a `critical` cross-cluster finding and exit 2.

> **Limitation:** this is pattern matching without context. A page *about*
> blocking adult content, a parental-control product, or a news article can
> trip `critical` keywords and classify as ADULT. Since `check` gates deploys on
> this, tune `thresholds.adultScore` for your fleet and treat a surprising
> ADULT verdict as "inspect the signals" (`peep classify -v`) rather than
> ground truth.

## Correlation

The `correlate` and `report` commands compute a pairwise similarity matrix across all fleet domains. Findings are categorized by severity:

| Severity | Examples |
|---|---|
| **critical** | Shared GA4/AdSense/GTM/Umami ID, shared Facebook pixel, shared Plausible `data-domain`, shared account-level vendor key (Stripe, PayPal, Google Ads, Mailchimp, Shopify store, Sentry DSN, TikTok/LinkedIn/Pinterest/Snap/X/Reddit pixel, Bing UET, Yandex, Hotjar, Segment, Mixpanel, Amplitude, PostHog, Klaviyo), TLS SAN covering both domains, adult content on clean site, shared Google/Bing/Facebook DNS verification tokens, SPF `include:`/`redirect=` naming another fleet domain, DMARC/CAA reports sent to a mailbox on another fleet domain, shared CAA `accounturi=` |
| **high** | Shared favicon hash, same IP (cross-cluster), shared registrant org, identical ads.txt, shared ads.txt pub-ids across clusters, shared JSON-LD `sameAs` URLs, shared JS content hashes (cross-cluster), shared form/booking endpoints (Formspree, Calendly, etc.), shared Clarity project, shared self-hosted Plausible/Umami instance, shared workspace-level vendor key (Intercom, Crisp, Tawk, HubSpot, reCAPTCHA/hCaptcha/Turnstile site key, Google API key, Firebase, Webflow, Cookiebot, OneSignal, …), same DMARC `rua`/`ruf` or CAA `iodef` mailbox on 2+ sites, shared SPF sender IP (cross-cluster), shared CSP/NEL report collector (`<account>.report-uri.com`, Sentry ingest, identical endpoint) |
| **medium** | Shared MX records (cross-cluster), registration dates within 7 days, shared meta generator (cross-cluster), shared affiliate redirect paths across clusters, shared CSS content hashes (cross-cluster), shared `twitter:site` handle, shared form/booking provider declared in CSP (Calendly/Formspree, fleet-wide or pairwise), shared non-commodity SPF `include:` (cross-cluster) |
| **low** | Shared nameservers, shared robots.txt hash, shared font sources, shared sitemap URL patterns, shared IP (same cluster), shared MX/head structure/generator/CSS/JS/SPF (same cluster — downgraded) |

**Same-cluster scoring**: Infrastructure findings (MX, head/body structure, generator, inline scripts, CSS, favicon) between domains in the same cluster are automatically downgraded in severity, since sharing is expected within a cluster. Cross-cluster sharing of the same signals remains at full severity.

**Commodity vs. genuine signals**: Signals shared by "any Cloudflare + Astro" site (nameservers, MX, bulk-mailer SPF includes such as `_spf.google.com`/`sendgrid.net`, the hosted `plausible.io` script, popular webfonts, sitemap/robots templates, generic generator/server/cookie headers) are weighted low in the similarity matrix and discounted in the isolation score, so unrelated brands on the same stack don't read as linked. Operator-specific signals (favicon, TLS SAN, shared form/booking handle, first-party JS, analytics IDs) carry the most weight.

**Coverage caveat**: sites whose fetch failed or that returned an error status contribute only DNS/TLS/WHOIS signals — none of their HTML, analytics or asset fingerprints were observed. The report lists them under `Coverage: n/N sites reachable` (JSON: `unreachable[]`) and the "looks good" verdict is annotated, so 7 dead sites out of 10 can't masquerade as a well-isolated fleet.

The **isolation score** (0-100, higher = better) uses a normalized penalty formula:

- **Fleet-wide penalties** (shared tracking IDs, cross-cluster violations, DNS verification tokens) apply at full weight: `criticals×25 + highs×10 + mediums×5 + lows×2`
- **Pairwise penalties** (per-pair findings) are normalized by `ceil(C(n,2)/3)` so large fleets don't auto-zero from expected infrastructure overlap
- Formula: `score = max(0, 100 − fleetPenalty − round(pairwisePenalty / normalizer))`

A 9-domain single-cluster fleet sharing only commodity infrastructure (MX + templates) stays well-isolated, since those signals are discounted; the same fleet with a shared GA4 ID still drops to 75. Scores below `correlationWarning` trigger exit code 1; any critical finding triggers exit code 2.

## `peep diff` — Snapshot Comparison

Compare two JSON outputs from any `peep` command to track changes over time:

```bash
peep diff audit-2026-01.json audit-2026-02.json
peep diff scan-before.json scan-after.json -j
```

Shows: new/resolved correlation findings, new/removed domains, analytics and third-party ID changes (GA4, AdSense, GTM, Facebook pixel, Clarity, and every vendor key such as a new Stripe key or chat widget appearing on a deploy), SPF/DMARC posture drift, noindex status changes (NOINDEX→LIVE or LIVE→NOINDEX), adult score changes >= 10 points, security-score and SEO-score drift, SEO checks that started/stopped failing, and — for `--pages` route audits present in both files — per-page SEO score, failing checks, canonical and noindex changes (e.g. "/de lost its og:image" between two deploys).

`diff` compares only these semantic fields. Volatile data — timestamps, timings, TLS expiry countdowns, per-build asset hashes — is never compared, so a Next.js redeploy with no real change diffs clean.

## `peep check` — Deploy Gate

Run as a CI/CD gate before deploying a domain:

```bash
peep check mysite.com --cluster clean
peep check mysite.com --min-score 70
peep check mysite.com --require-security-txt
peep check mysite.com --require-email-auth              # SPF -all/~all + DMARC quarantine/reject
peep check mysite.com --cluster clean --allow-noindex   # pre-launch: noindex is intentional
peep check mysite.com --only tls,robots                  # gates whose scanner didn't run are noted, not failed
peep check mysite.com --pages /de,/en --require-seo "Open Graph,Canonical URL" --min-seo 80
```

Exit 0 only if **all** of:
- Root URL answers with a non-error status (a 4xx/5xx — e.g. Cloudflare 526 origin-cert error — fails outright; Cloudflare 52x codes are explained in plain words)
- No adult signals detected (if `--cluster clean`)
- Site is **not** NOINDEX (indexable by search engines) — unless declared
  pre-launch, see below
- Security header score >= `--min-score` (default: 50)
- `security.txt` present (if `--require-security-txt`)
- SPF published with `-all`/`~all` and DMARC with `p=quarantine|reject` (if `--require-email-auth`) — a storefront that sends order mail from a domain with no DMARC is both spoofable and headed for spam
- SEO score of the root page and every `--pages` route >= `--min-seo` (if given); the failure names the checks that dragged it down
- Every check named in `--require-seo` (e.g. `"Open Graph"`) rates *good* on the root page and every `--pages` route — the "a page lost its `og:image` in this deploy" gate
- Every `--pages` route answers 2xx and is not noindex (unless declared pre-launch)
- No critical scan errors (DNS/HTTP/TLS)

Exit 1 with a clear explanation of what failed.

### Pre-launch noindex

A deliberate pattern before go-live: the site is public (so a payment
provider can review it) but kept `noindex` until launch. The plain gate
correctly fails that — it can't tell "forgot to remove noindex" from
"intentionally not launched yet". `--expect noindex` (alias `--prelaunch`)
disambiguates:

```bash
peep check mysite.com --cluster clean --expect noindex
peep check mysite.com --cluster clean --prelaunch        # same thing
```

The noindex failure becomes a PASS annotated `noindex (declared pre-launch)`;
every other check (adult content, security score, critical errors) still
gates normally. The flag is per-invocation only — it is never read from
`.peeprc` — so it can't quietly keep passing after the site actually launches
and someone forgets to remove noindex.

## Email authentication (SPF / DMARC / CAA)

The `dns` scanner reads the apex `v=spf1` TXT, the `_dmarc.<domain>` TXT and
CAA records and prints a verdict per record:

```
    CAA: issue letsencrypt.org, iodef mailto:certs@example.com
    + SPF: -all · include: _spf.google.com — hard fail for unlisted senders
    ~ DMARC: p=none rua=dmarc@example.com — p=none — monitoring only, spoofed mail is still delivered
```

- **SPF** — `-all` / `~all` is good; `?all`, no terminal, or `+all` is weak/bad;
  more than 10 `include:`/`redirect=` terms exceeds the DNS-lookup limit
  (permerror). A domain that never sends mail should still publish
  `v=spf1 -all`.
- **DMARC** — `p=reject`/`quarantine` is good; `p=none` (monitoring) and
  `pct<100` are warnings; missing means SPF/DKIM failures are never enforced.
- **DKIM** — informational: common selectors (`default`, `google`, `resend`,
  `zoho`, `k1`, `selector1/2`, …) are probed at `<sel>._domainkey.<domain>`;
  a hit lists the selectors, a miss says which were probed (a sender's real
  selector may not be in the list, so this never fails `--require-email-auth`).
  DKIM present + `p=none` adds the hint *safe to move to p=quarantine*.

Beyond posture, these records are **ownership signals** the correlation stage
uses: the same `rua=` mailbox on two domains is the same mail administrator; an
`include:` that names another fleet domain, or reports delivered to a mailbox
on another fleet domain, is an explicit cross-domain link written into DNS.
Bulk-mailer includes (`_spf.google.com`, `sendgrid.net`, …) are commodity and
ignored. `peep fleet` lists every spoofable domain in one block, and `peep diff`
reports SPF/DMARC drift between two snapshots.

## Scanning hostile targets

peep's job is pointing itself at domains it doesn't control, so page content is
treated as untrusted input:

- **SSRF guard** — a scanned page controls its own `<link rel="icon">`,
  stylesheet and `<script src>` values. Those subresource URLs are only fetched
  when they resolve to a public address, so a page can't aim peep at
  `169.254.169.254` (cloud metadata), `127.0.0.1`, or RFC1918 space. Non-HTTP
  schemes (`file:`, `javascript:`, `data:`) are rejected outright. IPv4-mapped
  IPv6 (`::ffff:127.0.0.1`) is unwrapped and judged by the embedded address.
- **Target host stays trusted** — the guard only applies to URLs harvested from
  page content. A subresource on the host you asked peep to scan is always
  allowed, so `peep scan http://localhost:3000` against a local build works.
- **Response size caps** — a timeout bounds how *long* a response may take, not
  how much it may send. Bodies are read through a byte ceiling (10 MB for
  pages, 5 MB for assets). Truncation is deterministic, so content hashes stay
  comparable across domains.
- **Bounded patterns** — extractor regexes use bounded spans instead of
  unbounded `.*?`, so a crafted page can't drive quadratic matching and stall a
  fleet scan.

## JSON output

`-j` / `--format json` emits the full `ScanResult`. Additive fields exist
for fleet tooling (pulse, brief) so every tool reads one shape:

- `findings[]` — every non-good security header, SEO check and SPF/DMARC/DKIM
  check as `{ id, scope: 'site', severity: 'crit'|'warn', title, detail, hint }`,
  ids `sec:<domain>/<header>`, `seo:<domain>/<check>`, `email:<domain>/<spf|dmarc|dkim>`
  (`missing`/`bad` → `crit`, `warning` → `warn`).
- `whois.expiresIn` — days until the registration expires (negative = expired,
  `null` when unknown), present whenever the whois scanner ran.
- `exposedIdentifiers[]` — e-mail addresses seen in DMARC `rua`/`ruf`, CAA
  `iodef`, `security.txt` and the page itself, with their source.

Volatile fields (`timestamp`, `duration`, `http.timing`, TLS expiry, per-build
asset hashes) are never compared by `peep diff`; its footer says how many
fields were compared and which were ignored.

## Configuration

Create a `.peeprc` file (JSON). Searched in order:

1. Path given via `--config`
2. `./.peeprc`
3. `./.peeprc.json`
4. `~/.peeprc`

```json
{
  "fleet": {
    "domains": ["site-a.com", "site-b.com", "site-c.com"],
    "clusters": {
      "clean-1": ["site-a.com", "site-b.com"],
      "adult": ["site-c.com"]
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
    "userAgent": "Mozilla/5.0 ...",
    "followRedirects": true,
    "whoisEnabled": true,
    "hashContent": true
  }
}
```

- **`fleet.domains`** — list of domains to scan. Domain names are normalized (protocol + trailing slash stripped). If empty but `fleet.clusters` has entries, domains are auto-populated from all cluster values.
- **`fleet.clusters`** — named groups; cluster names starting with `"adult"` are treated as adult clusters
- **`thresholds.adultScore`** — content score >= this classifies a site as ADULT (default: 30)
- **`thresholds.correlationWarning`** — isolation score < this triggers exit code 1 (default: 40)
- **`thresholds.correlationCritical`** — used in critical finding logic (default: 70)
- **`scanning.concurrency`** — max parallel domain scans (default: 5)
- **`scanning.timeout`** — HTTP/TLS/asset fetch timeout in ms (default: 15000)
- **`scanning.whoisEnabled`** — set `false` to disable WHOIS globally (default: true)
- **`scanning.hashContent`** — fetch and hash CSS/JS content instead of just URLs (default: true; toggle per-run with `--hash-content` / `--skip-content-hash`)

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All clear |
| 1 | Warnings — isolation score below `correlationWarning` threshold, or `check` failed |
| 2 | Critical — shared tracking IDs, cross-cluster violations, adult content on clean sites |

## Development

```bash
npm run dev       # tsc --watch
npm test          # compile tests + node --test
npm run lint      # tsc --noEmit (type-check)
```
