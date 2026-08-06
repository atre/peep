# Contributing to peep

Thanks for your interest! Bug reports, feature requests, and PRs are all welcome.

## Setup

```bash
git clone https://github.com/atre/peep.git
cd peep
npm install
npm run build
npm link        # optional: makes `peep` available globally
```

Requires Node.js 20+. The `whois` CLI binary is optional — peep falls back to
RDAP when it's unavailable.

See [ARCHITECTURE.md](ARCHITECTURE.md) for how the scanner phases, correlation
matrix, and DNS override fit together.

## Workflow

```bash
npm run dev      # tsc --watch
npm test         # compile tests + node --test
npm run lint     # tsc --noEmit
```

## Rules

- **Zero runtime npm dependencies.** Node built-ins + global `fetch` only — this is a hard constraint, not a preference. New features must be built without adding a dependency.
- Scanner results must conform to the types in `src/types.ts`.
- Phase 1 scanners (`dns`, `http`, `tls`, `whois`, `robots`) run in parallel and must not depend on each other's output. Phase 2 (`html`, `analytics`, `assets`, `content`) needs HTML from phase 1. Phase 3 (`security`, `tech`) needs headers from phase 1.
- Pattern lists in `src/patterns/` are append-only — don't restructure existing entries.

## Pull requests

Keep PRs focused on one change. Add/update tests under `test/` for any behavior change, and make sure `npm test` and `npm run lint` pass. Keep the README's flag/scanner tables and `peep --help` in sync with any CLI change.

## Reporting bugs

Open an issue with the exact command, expected vs actual behavior, and your OS/Node version. For scan-result issues, include the `-j` JSON output (redact any domain you don't want public) and whether `-v` shows a scanner error.
