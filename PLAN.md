# peep — improvement backlog

> **How to run this plan (agent):** read `CLAUDE.md` first; work top-down inside a phase; each open item states *what / why / accept* — do not tick `[x]` until its accept check passes; tests never touch the network or the real cluster (fixtures); `snuff` green = done (Stop hook runs it); append friction to `FEEDBACK.md`; never `git commit`/`push` unless the user says so; ask only when two readings lead to materially different work — otherwise pick the simpler one and say so.

Actionable items distilled from `FEEDBACK.md` (field runs 2026-08-15/16 on a storefront + a personal site). Ranked. Tick and move to CHANGELOG when shipped.
_All P0–P4 items from the 2026-08-15/16 field runs shipped in 0.3.0 — see CHANGELOG.md. Add new items below._

## Keep (confirmed good in the field)
`[NOINDEX]` banner · per-page `~`/`-` SEO misses · Security score with reasoned `+`/`~` lines · SPF/DMARC/CAA judged · `security.txt` facts inline · `check` FAIL → ✗ lines → status strip · sub-second scan incl. WHOIS/RDAP with DNSSEC.

## Fleet review 2026-08-17 (hub TOOLS.md Round 4) — this section is the queue

Verdict: **USED** (43 real calls / 6 sessions / 30d, `/opsec-check` ×2; FEEDBACK 6 use-sections). All 0.3.0 accepts verified 2026-08-17.
_Shared account-id correlation, DMARC fix string, fleet roll-up, route-weighted JSON-LD scoring, repo shape, and CLAUDE.md:24 shipped in 0.4.0 — see CHANGELOG.md._
- [ ] **`--pages all` via sitemap** — reuse looksy's `sitemap.ts` (copy until clikit); why: FEEDBACK:63. `pull` (after looksy ships it)
Parked: `findings[]` consumers (pulse `--opsec`, domain expiry) — pulse-side, gated on pulse dogfooding. Rule: no new emitter until a consuming test exists.

## Memory sanity-check 2026-08-18
_Local-target scan hygiene + `--host` shipped in 0.4.0 — see CHANGELOG.md._
Parked: offensive-recon roadmap (proxy/UA rotation, JA3, crt.sh/Shodan pivots, subdomain enum, `peep discover`, STIX/MISP export — 20 tasks, memory `project_offensive_roadmap`). Zero shipped across 0.2.0/0.3.0; both releases went all-defensive (account-id/DMARC/SEO correlation) driven by real dogfooding instead. Needs an explicit go/drop call before it's live backlog again — not touching until then.
