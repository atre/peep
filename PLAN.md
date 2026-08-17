# peep — improvement backlog

> **How to run this plan (agent):** read `CLAUDE.md` first; work top-down inside a phase; each open item states *what / why / accept* — do not tick `[x]` until its accept check passes; tests never touch the network or the real cluster (fixtures); `snuff` green = done (Stop hook runs it); append friction to `FEEDBACK.md`; never `git commit`/`push` unless the user says so; ask only when two readings lead to materially different work — otherwise pick the simpler one and say so.

Actionable items distilled from `FEEDBACK.md` (field runs 2026-08-15/16 on a storefront + a personal site). Ranked. Tick and move to CHANGELOG when shipped.
_All P0–P4 items from the 2026-08-15/16 field runs shipped in 0.3.0 — see CHANGELOG.md. Add new items below._

## Keep (confirmed good in the field)
`[NOINDEX]` banner · per-page `~`/`-` SEO misses · Security score with reasoned `+`/`~` lines · SPF/DMARC/CAA judged · `security.txt` facts inline · `check` FAIL → ✗ lines → status strip · sub-second scan incl. WHOIS/RDAP with DNSSEC.

## Fleet review 2026-08-17 (hub TOOLS.md Round 4) — this section is the queue

Verdict: **USED** (43 real calls / 6 sessions / 30d, `/opsec-check` ×2; FEEDBACK 6 use-sections). All 0.3.0 accepts verified 2026-08-17.
- [ ] **Shared account-id correlation** — Formspree form id / Calendly handle / GA-GTM already covered → same third-party account id on ≥ 2 domains = HIGH finding in `correlate`; why: FEEDBACK:59 (the leak that de-anonymises a store) · accept: fixture two ScanResults sharing `formspree:abc` → one HIGH `shared-account-id`. `pull/gold`
- [ ] **DMARC fix string on the ✗ line** — `✗ DMARC p=none → set v=DMARC1; p=quarantine; rua=mailto:…`; why: FEEDBACK:61 · accept: text output contains the literal record. `pull/gold`
- [ ] **`--pages all` via sitemap** — reuse looksy's `sitemap.ts` (copy until clikit); why: FEEDBACK:63. `pull` (after looksy ships it)
- [ ] **fleet roll-up** — `fleet` prints "same check fails on N/10 domains" block; why: FEEDBACK:62. `pull`
- [ ] **route-weighted JSON-LD scoring** — product/article routes weigh structured data, legal pages don't; why: FEEDBACK:60. `pull`
- [ ] **Repo shape** — add `skills/opsec-check/SKILL.md` (canonical) and symlink `~/.claude/skills/opsec-check` to it (today a loose copy from Aug 6); Stop hook `snuff --hook` in `.claude/settings.json`; `--version` fixed 2026-08-17. `hygiene`
- [ ] **CLAUDE.md:24 "zero-dep is a hard constraint"** → align with hub contract (deps allowed when they earn their keep). `hygiene`
Parked: `findings[]` consumers (pulse `--opsec`, domain expiry) — pulse-side, gated on pulse dogfooding. Rule: no new emitter until a consuming test exists.
