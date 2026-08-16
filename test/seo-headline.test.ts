import { test } from 'node:test';
import assert from 'node:assert/strict';
import { seoHeadline, pageSeoLabel } from '../src/commands/scan.js';
import type { SeoResult, SeoCheck, PageAudit } from '../src/types.js';

const good: SeoCheck = { name: 'robots.txt', present: true, value: 'present', rating: 'good', detail: 'robots.txt found' };
const oneWarning: SeoCheck = { name: 'Hreflang', present: false, value: null, rating: 'warning', detail: 'No hreflang' };

const pageAuditShell: PageAudit = {
  route: '/de', url: 'https://x.com/de', statusCode: 200, ok: true, title: null, htmlLang: null,
  canonicalUrl: null, isNoindex: false, hreflang: [], seoScore: null, seoIssues: [], formEndpoints: [],
};

test('partial --only run (evaluated < total) → "N/total evaluated (partial)"', () => {
  // Deviates from the backlog's literal example string ("SEO 2/2 evaluated
  // (partial)") which conflated evaluated with total — using the real total
  // (12) is what makes the label mean anything as a fraction.
  const seo: SeoResult = { score: 100, checks: [good, good], evaluated: 2, total: 12 };
  assert.equal(seoHeadline(seo), 'SEO 2/12 evaluated (partial)');
});

test('full evaluation (evaluated === total) → plain score', () => {
  const seo: SeoResult = { score: 92, checks: [good], evaluated: 12, total: 12 };
  assert.equal(seoHeadline(seo), 'SEO 92/100');
});

test('noindex-skipped checks do not count as partial', () => {
  const seo: SeoResult = { score: 100, checks: [good], evaluated: 9, total: 12, skipped: ['Canonical URL', 'Hreflang', 'Structured Data'] };
  assert.equal(seoHeadline(seo), 'SEO 100/100');
});

test('score null (fetch failed) → not evaluated label', () => {
  const seo: SeoResult = { score: null, checks: [], evaluated: 0, total: 12 };
  assert.equal(seoHeadline(seo), 'SEO not evaluated (fetch failed)');
});

// ── pageSeoLabel: per-page "(N/total pass)" ──

test('pageSeoLabel: appends passing count', () => {
  const p: PageAudit = { ...pageAuditShell, seoScore: 92, seoEvaluated: 12, seoIssues: [oneWarning] };
  assert.equal(pageSeoLabel(p), 'SEO 92/100 (11/12 pass)');
});

test('pageSeoLabel: seoEvaluated undefined (older JSON) → bare score', () => {
  const p: PageAudit = { ...pageAuditShell, seoScore: 92, seoIssues: [oneWarning] };
  assert.equal(pageSeoLabel(p), 'SEO 92/100');
});

test('pageSeoLabel: seoScore null → n/a', () => {
  assert.equal(pageSeoLabel(pageAuditShell), 'SEO n/a');
});
