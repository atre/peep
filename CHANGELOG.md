# Changelog

## 0.4.0 — 2026-08-18

Fleet review response (hub TOOLS.md Round 4, 2026-08-17) plus a memory sanity-check fix (2026-08-18): correlation completeness, fleet-wide rollups, route-aware SEO scoring, and local-target scan hygiene.

### Breaking
- **`peep fleet --format json` / `peep correlate --format json` top-level shape changed**: was a bare `ScanResult[]` array, now `{ results, check: { results, rollup } }` — `results` is the old array (unchanged), `check.results` is per-domain deploy-gate pass/fail, `check.rollup` is the new cross-domain rollup. Any JSON consumer indexing/iterating the array directly needs to read `.results` instead.

### Wrong or misleading output fixed
- **`fleet`/`correlate` silently dropped `--pages`/`--page-routes`** — per-page markup (e.g. a Formspree id only present on `/contact`) was invisible to `shared-form-endpoint`/`fleet-wide-form-endpoint` correlation unless the homepage itself carried it. `buildFleetScanOptions()` now forwards pages/routes to every domain scan.
- **Structured Data no longer scored on legal/utility pages** (`/privacy`, `/terms`, `/legal`, `/imprint`, `/cookies`, case-insensitive, segment-anchored) — `isLegalUtilityRoute()` gates the check out via the existing `seo.skipped` pattern, with a new `SeoResult.skipReasons` map explaining why (`"legal/utility page — schema not expected"`).
- **Local (`http://`) targets no longer read as broken or spoofable** — TLS and WHOIS now print `skipped (explicit http:// target)` instead of throwing/failing raw, and DNS-derived SPF/DMARC/CAA crit findings (meaningless for a target with no real DNS) are suppressed for explicit `http://` scans.

### Ergonomics
- **Copy-pasteable DMARC fix**: `check`'s DMARC ✗ line now appends `→ fix: set _dmarc TXT "v=DMARC1; p=quarantine; rua=mailto:…"`, preferring a real discovered contact address (existing rua, security.txt, CAA iodef, HTML mailto) over a placeholder.
- **`--host <domain>`**: overrides the TLS SNI hostname and HTTP `Host` header, so a preview/staging URL (`https://pr-123.vercel.app`) can be scanned *as* the real domain. Node's global `fetch()` drops a `Host` header (WHATWG forbidden-header-name), so this path uses a raw `node:http`/`node:https` fetch — only when `--host` is set; the default fetch path is untouched. Known gap: `robots.ts`/`assets.ts` don't yet honor `--host` (tracked in FEEDBACK.md).

### Fleet plumbing
- **Deploy-gate rollup**: `fleet` now runs the same `evaluateCheck()` gate as `check`, per domain, and rolls up a failure repeated across domains into one line — `same check fails on 6/10 domains: DMARC missing`, or route-scoped `/contact/: Title on 4/10 domains` — instead of repeating it per domain. Default text shows the rollup only; `-v` adds full per-domain detail; `--format json` always includes both (see Breaking, above).

### Repo hygiene
- Canonical `skills/opsec-check/SKILL.md` refreshed to 0.3.0 (`--lang`/`--brief`/`--fleet`, `--min-seo`/`--require-seo`/`--expect-hreflang`, `--stage pre-launch`, DKIM, per-page `SEO n/12 evaluated`, `findings[]`/`hint`, noindex-aware skip, 40+ vendor-id correlation signals); `~/.claude/skills/opsec-check` now symlinks to it instead of carrying a stale loose copy.
- `CLAUDE.md`'s dependency line reworded: zero-dep was never a hard rule, just today's state — deps are allowed when they earn their keep (pin them, prefer small well-known packages). The Stack section's "Zero runtime npm deps" line is untouched; `dependencies` is still absent from `package.json`.

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
