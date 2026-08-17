# Changelog

## 0.3.0 — 2026-08-17

Field-feedback round (storefront + personal site runs, 2026-08-15/16) plus fleet plumbing.

### Wrong or misleading output fixed
- **noindex pages** no longer scored on Canonical URL / Hreflang / Structured Data — skipped, listed in `seo.skipped`, headline says so.
- **No `Accept-Language` by default** (matches Googlebot); `--lang <xx>` to send one. The header actually sent is printed under `HTTP`. Fixes a DE-default store being audited on its EN variant.
- **`peep diff`** prints `compared N field(s), ignored M volatile (…)` so `0 change(s)` is trustworthy; `VOLATILE_FIELDS` exported, `DiffReport.compared` in JSON.
- **`--only whois`** now prints `WHOIS: unavailable (<reason>)` instead of nothing when the lookup fails.
- **Partial `--only` runs** headline as `SEO n/12 evaluated (partial)` instead of a misleading `/100` (`seoHeadline()`, reused by `check`).

### Less generic, more contextual
- Hreflang on an i18n site's untranslated page says so (`site is i18n (root: en, de, x-default) — this page has none…`); `check --expect-hreflang /blog/*:none` exempts routes.
- **Exposed identifiers** line (e-mails from DMARC rua/ruf, CAA iodef, security.txt, mailto:/body); fleet-wide `shared-contact-email` correlation (high).
- Title/description length: ±5 chars around the optimal range is `good` "borderline", not a warning.
- `Access-Control-Allow-Origin: *` on Cloudflare Pages annotated `(host default; override in _headers)`.
- `N analytics vendors (GA4, …)` note when ≥ 2 tracking vendors present.
- **DKIM**: common selectors probed; listed next to SPF/DMARC (informational, never fails `--require-email-auth`); DKIM present + `p=none` → "safe to move to p=quarantine".

### Ergonomics
- `check --stage pre-launch` alias for `--expect noindex` (any other `--stage` value is fatal).
- `humans.txt` / `ads.txt` one-line facts (`— 3 lines, Contact: …`, `— N pub-id(s): …`).
- Per-page audits show `SEO 92/100 (11/12 pass)`; `PageAudit.seoEvaluated` in JSON.

### Fleet plumbing
- **`fleet.yaml`** (`domains`, `pages`, `locales`, `viewports` — shared with looksy/texter/trusty) read from `./fleet.yaml` or `--fleet <path>`; `domains` default the fleet, `pages` default `--pages`. Explicit `.peeprc` / flags win.
- **`--brief`**: red-only, ≤ 10 lines per domain, implies `-q`; on `scan`, `check`, `fleet`.
- **`findings[]`** in every scan JSON in pulse's Finding shape (`scope: 'site'`, ids `sec:`/`seo:`/`email:`, `crit`/`warn`); **`whois.expiresIn`** (days) always present when whois ran. Findings carry a `hint` (`peep scan <domain> --only security|seo|dns`) per the fleet contract. Note: `peep check` skips whois unless `--only whois` — domain-expiry consumers use `peep scan <domain> --only whois -j`.

## 0.2.0 — 2026-08-16
Third-party account IDs, email OPSEC (SPF/DMARC/CAA), report collectors.
