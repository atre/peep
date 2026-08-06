export class Semaphore {
  private queue: Array<() => void> = [];
  private running = 0;

  constructor(private readonly max: number) {}

  async acquire(): Promise<void> {
    if (this.running < this.max) {
      this.running++;
      return;
    }
    return new Promise<void>((resolve) => {
      this.queue.push(resolve);
    });
  }

  release(): void {
    this.running--;
    const next = this.queue.shift();
    if (next) {
      this.running++;
      next();
    }
  }
}

export interface ConcurrentOptions {
  /** Minimum delay in ms between starting each item (rate limiting). Default: 0 */
  delayMs?: number;
  /** Random jitter in ms added to delay (0 to jitterMs). Default: 0 */
  jitterMs?: number;
}

export async function mapConcurrent<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<R>,
  opts?: ConcurrentOptions,
): Promise<R[]> {
  const sem = new Semaphore(concurrency);
  const delayMs = opts?.delayMs ?? 0;
  const jitterMs = opts?.jitterMs ?? 0;

  // Serialize rate-limit checks via a promise chain to prevent data races
  // when multiple promises read/write lastStart concurrently
  let lastStart = 0;
  let delayGate = Promise.resolve();

  const results = items.map(async (item) => {
    await sem.acquire();
    try {
      if (delayMs > 0 || jitterMs > 0) {
        await (delayGate = delayGate.then(async () => {
          const now = Date.now();
          const elapsed = now - lastStart;
          const totalDelay = delayMs + Math.floor(Math.random() * jitterMs);
          if (elapsed < totalDelay) {
            await new Promise((r) => setTimeout(r, totalDelay - elapsed));
          }
          lastStart = Date.now();
        }));
      }
      return await fn(item);
    } finally {
      sem.release();
    }
  });
  return Promise.all(results);
}
