# peep

Fleet OPSEC scanner: fingerprint detection, grey-red classification, cross-site correlation.

## Stack
- TypeScript 5.x, Node ≥ 20, ESM only (`"type": "module"`)
- Zero runtime npm deps — built-ins + global fetch only
- devDeps: typescript, @types/node

## Commands
- `npm run build` — tsc → dist/
- `npm run dev` — tsc --watch
- `npm test` — compile → test-dist/, run node --test
- `npm run lint` — tsc --noEmit

## Architecture
- `src/scanners/` — 11 scanners across 3 phases + derived `seo` score (see README.md for phase order)
- `src/commands/` — scan, fleet, correlate, classify, report, diff, check
- `src/correlation/` — pairwise matrix + isolation scoring
- `src/patterns/` — keyword/network lists (adult, affiliate, ad)
- `src/types.ts` — shared types for all scanner results

## Rules
- NO runtime npm dependencies — zero-dep is a hard constraint
- Scanner results must match types in src/types.ts
- Phase 1 scanners run parallel; phase 2 needs html output; phase 3 needs headers

## Session Types
- Scanner dev: `src/scanners/` + `src/types.ts`
- Correlation/scoring: `src/correlation/` + `src/commands/correlate.ts`
- Pattern updates: `src/patterns/` only — append, don't restructure
