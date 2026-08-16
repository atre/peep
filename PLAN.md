# peep — improvement backlog

> **How to run this plan (agent):** read `CLAUDE.md` first; work top-down inside a phase; each open item states *what / why / accept* — do not tick `[x]` until its accept check passes; tests never touch the network or the real cluster (fixtures); `snuff` green = done (Stop hook runs it); append friction to `FEEDBACK.md`; never `git commit`/`push` unless the user says so; ask only when two readings lead to materially different work — otherwise pick the simpler one and say so.

Actionable items distilled from `FEEDBACK.md` (field runs 2026-08-15/16 on a storefront + a personal site). Ranked. Tick and move to CHANGELOG when shipped.
_All P0–P4 items from the 2026-08-15/16 field runs shipped in 0.3.0 — see CHANGELOG.md. Add new items below._

## Keep (confirmed good in the field)
`[NOINDEX]` banner · per-page `~`/`-` SEO misses · Security score with reasoned `+`/`~` lines · SPF/DMARC/CAA judged · `security.txt` facts inline · `check` FAIL → ✗ lines → status strip · sub-second scan incl. WHOIS/RDAP with DNSSEC.
