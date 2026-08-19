---
name: opsec-check
description: Fleet OPSEC scanning with the globally installed `peep` CLI — fingerprint detection, cross-site correlation, grey-red classification, deploy gates. TRIGGER before putting any site live, after a production deploy, on "can these sites/domains be linked", periodic fleet audits, or domain fingerprint questions — from any site-fleet repo. SKIP for visual/design QA (use visual-qa) and for full pre-prod site QA inside the sites repo (its precheck skill already includes the peep gate).
---

# OPSEC Check (peep)

Detects signals that could reveal common ownership across a fleet of domains: shared analytics/third-party account IDs, favicon/asset hashes, TLS SAN overlap, WHOIS registrant matches, DNS/SPF/DMARC/CAA patterns, HTML structure fingerprints.

## Deploy gate (the common case)

```bash
peep check <domain> --cluster clean                          # exit 0 = pass, 1 = blocked
peep check <domain> --cluster clean --expect noindex          # pre-launch: deliberate noindex passes, annotated
peep check <domain> --cluster clean --stage pre-launch        # same, alias
peep check <domain> --require-email-auth                      # SPF -all/~all + DMARC quarantine/reject enforced
peep check <domain> --pages /de,/en --require-seo "Open Graph" --min-seo 80   # per-route SEO gate
```

Run after every production deploy of a new or changed site. Non-zero exit = report the named violations, fix, re-run — do not leave the site live unfixed without flagging it. `--expect noindex` (aliases `--prelaunch`, `--allow-noindex`, `--stage pre-launch`) is per-invocation only — never bake it into config; drop it the moment indexing turns on.

**Stale local DNS** (freshly cut-over domain, `getaddrinfo ENOTFOUND` while public DNS resolves): peep detects the mismatch and hints; add `--dns 1.1.1.1` to scan through the public resolver without touching system state.

## Single-domain fingerprint report

```bash
peep scan <domain>                                   # full text report
peep scan <domain> -j                                # JSON
peep scan <domain> --only dns,tls,analytics,assets   # targeted
peep scan <domain> --brief                            # red-only, ≤ 10 lines, for hooks/gates
peep scan <domain> --lang de                          # send Accept-Language (default: none, matches Googlebot)
peep scan <domain> --pages /de,/fr                    # per-page SEO/hreflang audit
```

Scanners: dns, http, tls, whois, html, analytics, assets, robots, content, security, tech. Derived scores: `security`, `seo` (`n/12 evaluated`; under a partial `--only`, unevaluated checks report "not evaluated", never failing; noindex pages skip Canonical URL / Hreflang / Structured Data and say so).

## Fleet operations (`.peeprc`, or `fleet.yaml` shared with looksy/texter/trusty)

```bash
peep fleet                    # scan all fleet domains
peep correlate                # cross-site correlation matrix — THE linkability answer
peep classify                 # grey-red content classification + cross-cluster violations
peep report --out audit.json  # full audit: scan + correlate + report file
peep diff audit-jan.json audit-feb.json   # what changed (prints "compared N field(s), ignored M volatile")
```

`--fleet <path>` reads `domains`/`pages` from `fleet.yaml` (default `./fleet.yaml`) when no `.peeprc` fleet is configured; an explicit `.peeprc` domains list or `--pages` always wins.

## Interpreting correlation hits

Highest-risk linkage signals, roughly in order: shared GA4/GTM/AdSense/third-party vendor keys (Stripe, PayPal, Sentry, Meta/TikTok/LinkedIn pixels, 40+ more) → identical favicon/asset hashes → TLS SAN overlap → WHOIS registrant match → shared DMARC/CAA report mailbox or an SPF `include:` naming another fleet domain → shared HTML structure hashes → same hosting/NEL/tech-stack patterns. Analytics IDs and favicons are the classic mistakes — check those first when a correlation is flagged.

## JSON contract

Every scan JSON carries `findings[]` in pulse's Finding shape (`scope: 'site'`, ids `sec:`/`seo:`/`email:`, severity `crit`/`warn`, each with a `hint` — the exact `peep scan <domain> --only ...` to re-run for detail) and `whois.expiresIn` (days) whenever whois ran. `peep check` skips whois unless `--only whois` is given — use `peep scan <domain> --only whois -j` for domain-expiry checks.

## Workflow for a new site going live

1. `peep scan <domain> -j` on the staging/live URL — fix any identity leaks (comments, security.txt, meta generators, email auth posture).
2. `peep correlate` with the rest of the fleet — confirm no new cross-links.
3. `peep check <domain> --cluster <cluster> --expect noindex` while still pre-launch, then the same command without the flag as the final go-live gate; archive a `peep report --out` snapshot for future `diff`.

Source + full docs: `~/git/peep` (peep 0.3.0 — `peep --version` / `peep -v` prints the running version, always read from package.json).
