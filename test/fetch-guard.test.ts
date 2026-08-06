import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { isFetchAllowed, isPrivateAddress, readCapped, readCappedBuffer } from '../src/fetch-guard.js';

// ── Private address classification ──

test('IPv4 private, loopback, link-local and reserved ranges are private', () => {
  for (const ip of [
    '0.0.0.0', '10.0.0.1', '10.255.255.255', '127.0.0.1', '127.1.2.3',
    '100.64.0.1', '169.254.169.254', '172.16.0.1', '172.31.255.255',
    '192.0.0.1', '192.168.1.1', '198.18.0.1', '224.0.0.1', '255.255.255.255',
  ]) {
    assert.equal(isPrivateAddress(ip), true, `${ip} should be private`);
  }
});

test('public IPv4 addresses are not private', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '104.16.0.1', '172.15.0.1', '172.32.0.1', '192.167.1.1']) {
    assert.equal(isPrivateAddress(ip), false, `${ip} should be public`);
  }
});

test('IPv6 loopback, unspecified, unique-local, link-local and multicast are private', () => {
  for (const ip of ['::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1']) {
    assert.equal(isPrivateAddress(ip), true, `${ip} should be private`);
  }
});

test('public IPv6 addresses are not private', () => {
  for (const ip of ['2606:4700::1111', '2001:4860:4860::8888']) {
    assert.equal(isPrivateAddress(ip), false, `${ip} should be public`);
  }
});

// Regression: `new URL()` rewrites [::ffff:127.0.0.1] to ::ffff:7f00:1, so a
// textual dotted-quad check let a mapped loopback address through.
test('IPv4-mapped IPv6 is judged by its embedded IPv4 address, in either notation', () => {
  for (const ip of ['::ffff:127.0.0.1', '::ffff:7f00:1', '0:0:0:0:0:ffff:7f00:1', '::ffff:169.254.169.254', '::ffff:a9fe:a9fe', '::ffff:10.0.0.1']) {
    assert.equal(isPrivateAddress(ip), true, `${ip} should be private`);
  }
  for (const ip of ['::ffff:8.8.8.8', '::ffff:808:808']) {
    assert.equal(isPrivateAddress(ip), false, `${ip} should be public`);
  }
});

test('malformed addresses fail closed', () => {
  for (const bad of ['not-an-ip', '999.999.999.999', '::gggg', '1:2:3::4:5::6', '']) {
    assert.equal(isPrivateAddress(bad), true, `${bad} should fail closed`);
  }
});

// ── SSRF guard on page-derived URLs ──

test('cloud metadata and internal addresses are blocked', async () => {
  for (const url of [
    'http://169.254.169.254/latest/meta-data/',
    'http://127.0.0.1:6379/',
    'http://10.0.0.5/internal',
    'http://192.168.1.1/',
    'http://[::1]:9200/',
    'http://[::ffff:127.0.0.1]/',
    'http://0.0.0.0/',
    'http://100.64.0.1/',
  ]) {
    const v = await isFetchAllowed(url, 'example.com');
    assert.equal(v.allowed, false, `${url} should be blocked`);
    assert.ok(v.reason, 'a blocked URL should explain why');
  }
});

test('non-HTTP schemes are blocked', async () => {
  for (const url of ['file:///etc/passwd', 'javascript:alert(1)', 'data:text/html,x', 'ftp://example.com/x']) {
    const v = await isFetchAllowed(url, 'example.com');
    assert.equal(v.allowed, false, `${url} should be blocked`);
  }
});

test('unparseable URLs are blocked', async () => {
  const v = await isFetchAllowed('http://[not a url', 'example.com');
  assert.equal(v.allowed, false);
});

test('public hosts are allowed', async () => {
  const v = await isFetchAllowed('https://1.1.1.1/favicon.ico', 'example.com');
  assert.equal(v.allowed, true);
});

// The scan target is trusted — `peep scan http://localhost:3000` must keep
// working, so a subresource on the target's own host is always allowed.
test('subresources on the scan target host are allowed even when private', async () => {
  for (const [url, host] of [
    ['http://localhost:3000/favicon.ico', 'localhost'],
    ['http://127.0.0.1:8080/main.css', '127.0.0.1'],
    ['http://192.168.1.50/app.js', '192.168.1.50'],
  ]) {
    const v = await isFetchAllowed(url, host);
    assert.equal(v.allowed, true, `${url} on target ${host} should be allowed`);
  }
});

test('a different private host is still blocked while scanning a local target', async () => {
  const v = await isFetchAllowed('http://169.254.169.254/latest/', 'localhost');
  assert.equal(v.allowed, false);
});

// ── Response size cap ──

async function serveBytes(totalBytes: number): Promise<{ url: string; close: () => void }> {
  const chunk = 'A'.repeat(64 * 1024);
  const server = createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    let sent = 0;
    const timer = setInterval(() => {
      if (sent >= totalBytes) {
        clearInterval(timer);
        res.end();
        return;
      }
      res.write(chunk);
      sent += chunk.length;
    }, 0);
    req.on('close', () => clearInterval(timer));
  });
  await new Promise<void>((r) => server.listen(0, r));
  const port = (server.address() as { port: number }).port;
  return { url: `http://127.0.0.1:${port}/`, close: () => server.close() };
}

test('readCapped truncates a body that exceeds the cap', async () => {
  const { url, close } = await serveBytes(8 * 1024 * 1024);
  try {
    const text = await readCapped(await fetch(url), 512 * 1024);
    assert.equal(text.length, 512 * 1024);
  } finally {
    close();
  }
});

test('readCapped returns a short body intact', async () => {
  const { url, close } = await serveBytes(64 * 1024);
  try {
    const text = await readCapped(await fetch(url), 5 * 1024 * 1024);
    assert.ok(text.length > 0 && text.length <= 128 * 1024, `unexpected length ${text.length}`);
  } finally {
    close();
  }
});

test('readCappedBuffer truncates binary bodies', async () => {
  const { url, close } = await serveBytes(4 * 1024 * 1024);
  try {
    const buf = await readCappedBuffer(await fetch(url), 256 * 1024);
    assert.equal(buf.length, 256 * 1024);
  } finally {
    close();
  }
});

test('truncation is deterministic, so content hashes stay comparable', async () => {
  const { url, close } = await serveBytes(2 * 1024 * 1024);
  try {
    const a = await readCapped(await fetch(url), 100 * 1024);
    const b = await readCapped(await fetch(url), 100 * 1024);
    assert.equal(a, b);
  } finally {
    close();
  }
});
