import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanHtml } from '../src/scanners/html.js';

const HTML_A = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Test Page</title>
  <meta name="description" content="A test page">
  <meta name="robots" content="noindex, nofollow">
  <meta property="og:title" content="OG Title">
  <meta property="og:url" content="https://example.com">
  <link rel="stylesheet" href="/main.css">
</head>
<body>
  <header class="site-header" id="header"><nav></nav></header>
  <main class="content"><p>Hello world</p></main>
  <footer class="site-footer"><p>Footer</p></footer>
  <script>// inline script</script>
  <!-- page comment -->
</body>
</html>`;

const HTML_B = `<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <title>Andere Seite</title>
  <meta name="description" content="Eine andere Seite">
  <link rel="stylesheet" href="/other.css">
</head>
<body>
  <header class="main-header" id="top"></header>
  <article class="post"><p>Inhalt</p></article>
</body>
</html>`;

test('title extracted correctly', () => {
  const r = scanHtml(HTML_A);
  assert.equal(r.title, 'Test Page');
});

test('metaDescription extracted', () => {
  const r = scanHtml(HTML_A);
  assert.equal(r.metaDescription, 'A test page');
});

test('OG tags extracted', () => {
  const r = scanHtml(HTML_A);
  assert.equal(r.ogTags['og:title'], 'OG Title');
  assert.equal(r.ogTags['og:url'], 'https://example.com');
});

test('noindex detected in metaRobots', () => {
  const r = scanHtml(HTML_A);
  assert.notEqual(r.metaRobots, null);
  assert.match(r.metaRobots!, /noindex/);
});

test('clean page has null metaRobots', () => {
  const r = scanHtml(HTML_B);
  assert.equal(r.metaRobots, null);
});

test('htmlLang extracted', () => {
  const r = scanHtml(HTML_A);
  assert.equal(r.htmlLang, 'en');
});

test('same HTML gives same structure hashes', () => {
  const r1 = scanHtml(HTML_A);
  const r2 = scanHtml(HTML_A);
  assert.equal(r1.headStructureHash, r2.headStructureHash);
  assert.equal(r1.bodyStructureHash, r2.bodyStructureHash);
});

test('different HTML gives different body structure hashes', () => {
  const r1 = scanHtml(HTML_A);
  const r2 = scanHtml(HTML_B);
  assert.notEqual(r1.bodyStructureHash, r2.bodyStructureHash);
});

test('HTML comments extracted', () => {
  const r = scanHtml(HTML_A);
  assert.ok(r.comments.some((c) => c.includes('page comment')));
});

test('stylesheet sources extracted', () => {
  const r = scanHtml(HTML_A);
  assert.ok(r.stylesheetSources.includes('/main.css'));
});

// ── JSON-LD extraction ──

test('JSON-LD Person with sameAs extracted', () => {
  const html = `<html><head>
    <script type="application/ld+json">
    {"@type":"Person","name":"Alice","url":"https://alice.com","sameAs":["https://twitter.com/alice","https://github.com/alice"]}
    </script>
  </head><body></body></html>`;
  const r = scanHtml(html);
  assert.equal(r.jsonLd.length, 1);
  assert.equal(r.jsonLd[0].type, 'Person');
  assert.equal(r.jsonLd[0].name, 'Alice');
  assert.equal(r.jsonLd[0].url, 'https://alice.com');
  assert.deepEqual(r.jsonLd[0].sameAs, ['https://twitter.com/alice', 'https://github.com/alice']);
});

test('JSON-LD @graph array extracted', () => {
  const html = `<html><head>
    <script type="application/ld+json">
    {"@graph":[{"@type":"Organization","name":"Acme","sameAs":"https://linkedin.com/acme"},{"@type":"WebSite","url":"https://acme.com"}]}
    </script>
  </head><body></body></html>`;
  const r = scanHtml(html);
  assert.equal(r.jsonLd.length, 2);
  assert.equal(r.jsonLd[0].type, 'Organization');
  assert.deepEqual(r.jsonLd[0].sameAs, ['https://linkedin.com/acme']);
  assert.equal(r.jsonLd[1].type, 'WebSite');
  assert.deepEqual(r.jsonLd[1].sameAs, []);
});

test('malformed JSON-LD is skipped', () => {
  const html = `<html><head>
    <script type="application/ld+json">{not valid json}</script>
  </head><body></body></html>`;
  const r = scanHtml(html);
  assert.equal(r.jsonLd.length, 0);
});

test('page without JSON-LD returns empty array', () => {
  const r = scanHtml(HTML_B);
  assert.deepEqual(r.jsonLd, []);
});

// ── Twitter card extraction ──

test('twitter:card and twitter:image extracted', () => {
  const html = `<html><head>
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="My Title">
    <meta name="twitter:image" content="https://example.com/img.png">
  </head><body></body></html>`;
  const r = scanHtml(html);
  assert.equal(r.twitterCards['twitter:card'], 'summary_large_image');
  assert.equal(r.twitterCards['twitter:title'], 'My Title');
  assert.equal(r.twitterCards['twitter:image'], 'https://example.com/img.png');
});

test('twitter tags with reversed attribute order extracted', () => {
  const html = `<html><head>
    <meta content="summary" name="twitter:card">
  </head><body></body></html>`;
  const r = scanHtml(html);
  assert.equal(r.twitterCards['twitter:card'], 'summary');
});

test('page without twitter tags returns empty object', () => {
  const r = scanHtml(HTML_B);
  assert.deepEqual(r.twitterCards, {});
});

// ── Form endpoint extraction ──

test('Formspree action URL extracted', () => {
  const html = `<html><body>
    <form action="https://formspree.io/f/xyzabc123">
      <input type="email"><button>Submit</button>
    </form>
  </body></html>`;
  const r = scanHtml(html);
  assert.equal(r.formEndpoints.length, 1);
  assert.ok(r.formEndpoints[0].includes('formspree.io'));
});

test('Calendly embed URL extracted', () => {
  const html = `<html><body>
    <iframe src="https://calendly.com/alice/30min"></iframe>
  </body></html>`;
  const r = scanHtml(html);
  assert.equal(r.formEndpoints.length, 1);
  assert.ok(r.formEndpoints[0].includes('calendly.com'));
});

test('page without form endpoints returns empty array', () => {
  const r = scanHtml(HTML_B);
  assert.deepEqual(r.formEndpoints, []);
});

test('Formspree URL in inline JS (fetch-based) extracted', () => {
  const html = `<html><body>
    <script>
      var url = "https://formspree.io/f/xyztest1";
      fetch(url, { method: "POST" });
    </script>
  </body></html>`;
  const r = scanHtml(html);
  assert.ok(r.formEndpoints.length >= 1);
  assert.ok(r.formEndpoints.some((e) => e.includes('formspree.io/f/xyztest1')));
});

test('Calendly data-url attribute extracted', () => {
  const html = `<html><body>
    <div class="calendly-inline-widget" data-url="https://calendly.com/mycompany/30min"></div>
  </body></html>`;
  const r = scanHtml(html);
  assert.ok(r.formEndpoints.length >= 1);
  assert.ok(r.formEndpoints.some((e) => e.includes('calendly.com/mycompany/30min')));
});

test('Calendly URL in inline JS extracted', () => {
  const html = `<html><body>
    <script>var calUrl = 'https://calendly.com/team/demo';</script>
  </body></html>`;
  const r = scanHtml(html);
  assert.ok(r.formEndpoints.length >= 1);
  assert.ok(r.formEndpoints.some((e) => e.includes('calendly.com/team/demo')));
});

test('duplicate form endpoints deduplicated', () => {
  const html = `<html><body>
    <form action="https://formspree.io/f/abc123"></form>
    <script>fetch("https://formspree.io/f/abc123")</script>
  </body></html>`;
  const r = scanHtml(html);
  const formspreeEndpoints = r.formEndpoints.filter((e) => e.includes('formspree.io'));
  assert.equal(formspreeEndpoints.length, 1, 'Should deduplicate same endpoint');
});

test('framework marker comments (React/Next Suspense, Angular anchors) are not counted as comments', () => {
  const html = `<html><body>
    <!--$--><div>a</div><!--/$-->
    <!--$?--><template></template><!--/$-->
    <!--$!--><!-- --><!---->
    <!--[--><span></span><!--]-->
    <!-- TODO: remove legacy tracking before launch -->
  </body></html>`;
  const r = scanHtml(html);
  assert.deepEqual(r.comments, ['TODO: remove legacy tracking before launch']);
});
