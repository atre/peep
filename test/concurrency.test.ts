import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Semaphore, mapConcurrent } from '../src/concurrency.js';

const tick = () => new Promise((r) => setTimeout(r, 5));

test('Semaphore allows up to max concurrent holders', async () => {
  const sem = new Semaphore(2);
  await sem.acquire();
  await sem.acquire();

  let third = false;
  const pending = sem.acquire().then(() => { third = true; });

  await tick();
  assert.equal(third, false, 'third acquire must block while 2 are held');

  sem.release();
  await pending;
  assert.equal(third, true, 'releasing one slot unblocks the waiter');
});

test('mapConcurrent preserves input order in results', async () => {
  // Reverse the delay so later items resolve first — output order must still match input
  const items = [1, 2, 3, 4, 5];
  const out = await mapConcurrent(items, 5, async (n) => {
    await new Promise((r) => setTimeout(r, (6 - n) * 4));
    return n * 10;
  });
  assert.deepEqual(out, [10, 20, 30, 40, 50]);
});

test('mapConcurrent never exceeds the concurrency cap', async () => {
  let inFlight = 0;
  let peak = 0;
  const items = Array.from({ length: 12 }, (_, i) => i);
  await mapConcurrent(items, 3, async (n) => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await tick();
    inFlight--;
    return n;
  });
  assert.ok(peak <= 3, `peak concurrency ${peak} should not exceed 3`);
  assert.ok(peak >= 2, `peak concurrency ${peak} should actually parallelize`);
});

test('mapConcurrent runs every item exactly once', async () => {
  const seen: number[] = [];
  const items = Array.from({ length: 20 }, (_, i) => i);
  const out = await mapConcurrent(items, 4, async (n) => { seen.push(n); return n; });
  assert.equal(out.length, 20);
  assert.deepEqual([...seen].sort((a, b) => a - b), items);
});

test('mapConcurrent handles an empty list', async () => {
  const out = await mapConcurrent([], 4, async (n) => n);
  assert.deepEqual(out, []);
});

test('mapConcurrent with delay spaces out item starts', async () => {
  const starts: number[] = [];
  const begin = Date.now();
  await mapConcurrent([1, 2, 3], 3, async () => { starts.push(Date.now() - begin); }, { delayMs: 20 });
  // Three items, ~20ms apart → last start should be >= ~30ms after the first
  assert.ok(starts.length === 3);
  assert.ok(starts[2] - starts[0] >= 25, `expected spacing from delayMs, got ${starts[2] - starts[0]}ms`);
});
