import dns from 'node:dns';

/**
 * Unify DNS resolution across scanners. The concrete bug this fixes: against a
 * freshly-cut-over domain, the `dns` scanner (dns.resolve4/6 — queries
 * configured nameservers directly via c-ares) resolved fine, while `http`
 * (fetch) and `tls` (tls.connect) both got `getaddrinfo ENOTFOUND` — they
 * resolve hostnames via dns.lookup(), which goes through the OS's own
 * resolver/cache (mDNSResponder, systemd-resolved, …) and still held a stale
 * negative-cache entry for the domain.
 *
 * fetch() and tls.connect() both call the public, unpatched `dns.lookup`
 * internally (verified empirically — Node doesn't expose a way to point
 * fetch's DNS resolution at a specific server otherwise, and this repo is
 * zero-runtime-deps, so no undici Agent/dispatcher). Patching `dns.lookup`
 * once, process-wide, is therefore the one intervention that makes every
 * scanner — `dns`'s own resolve4/6 calls are separate and untouched, but every
 * fetch()/tls.connect() caller (http, robots, assets, tech's page fetches,
 * whois's RDAP fallback, tls) — resolve through the same decision.
 */

export const DEFAULT_PUBLIC_RESOLVER = '1.1.1.1';

/** True for the class of dns.lookup() errors that mean "this name doesn't
 *  exist" per the OS resolver, as opposed to a timeout or network-down error
 *  that a second resolver can't meaningfully contradict. */
export function isNxdomainLike(code: string | null | undefined): boolean {
  return code === 'ENOTFOUND' || code === 'ENODATA';
}

/** The warning surfaced when the OS resolver disagrees with the public/
 *  configured one but --dns wasn't given, so we didn't act on it. */
export function staleResolverWarning(server: string, addresses: string[]): string {
  return `local resolver returned NXDOMAIN but ${server} resolves (${addresses.join(', ')}) — likely stale negative cache; retry with --dns ${server}`;
}

export interface ResolveDecision {
  /** Addresses the caller should actually connect with instead of failing.
   *  Empty when the OS resolver's failure stands. */
  addresses: string[];
  /** Attached to the original error when `addresses` is empty but a public
   *  resolver did disagree — explains why, without changing behavior. */
  warning: string | null;
}

/**
 * Decide what to do with an OS-resolver failure, given what the public/
 * configured resolver said. Pure — no I/O — so it's unit-testable without
 * touching the network or global `dns` state; see installDnsOverride() below
 * for the real wiring.
 */
export function decideResolution(
  osErrorCode: string | null | undefined,
  publicAddresses: string[],
  server: string,
  explicitDnsServer: boolean,
): ResolveDecision {
  if (!isNxdomainLike(osErrorCode) || publicAddresses.length === 0) {
    return { addresses: [], warning: null };
  }
  if (explicitDnsServer) {
    // The user opted in to trusting this server (--dns) — use its answer.
    return { addresses: publicAddresses, warning: null };
  }
  // Default: never silently override the OS resolver. Explain instead.
  return { addresses: [], warning: staleResolverWarning(server, publicAddresses) };
}

async function resolvePublicOrEmpty(hostname: string, server: string): Promise<string[]> {
  try {
    const resolver = new dns.promises.Resolver();
    resolver.setServers([server]);
    return await resolver.resolve4(hostname);
  } catch {
    return [];
  }
}

const REAL_LOOKUP = dns.lookup.bind(dns);
let installed = false;

/**
 * Install the process-wide dns.lookup() override described above. Safe to
 * call more than once (e.g. once per domain in a fleet scan) — only installs
 * on the first call, and a one-shot CLI process never needs to uninstall.
 *
 * Behavior:
 *  - OS resolver succeeds → returned as-is, byte-for-byte stock Node behavior.
 *  - OS resolver fails (ENOTFOUND/ENODATA) → cross-check the public/configured
 *    resolver (`dnsServer`, default 1.1.1.1):
 *    - disagreement + `dnsServer` explicitly passed (--dns) → use its answer.
 *    - disagreement + no --dns given → keep failing (never silently swap the
 *      default resolver), but attach `.peepResolverWarning` to the error so
 *      callers can explain *why* instead of a bare ENOTFOUND.
 *    - both agree there's nothing → the original OS error, untouched.
 */
export function installDnsOverride(dnsServer?: string): void {
  if (installed) return;
  installed = true;

  const server = dnsServer ?? DEFAULT_PUBLIC_RESOLVER;
  const explicit = dnsServer != null;

  dns.lookup = ((hostname: string, arg2: unknown, arg3?: unknown) => {
    const hasOptions = typeof arg2 !== 'function';
    const options = (hasOptions ? arg2 : {}) as dns.LookupOptions;
    const callback = (hasOptions ? arg3 : arg2) as (err: NodeJS.ErrnoException | null, address: unknown, family?: number) => void;

    REAL_LOOKUP(hostname, options as dns.LookupAllOptions, (err: NodeJS.ErrnoException | null, address: unknown, family?: number) => {
      if (!err) { callback(null, address, family); return; }

      resolvePublicOrEmpty(hostname, server).then((publicAddresses) => {
        const decision = decideResolution(err.code, publicAddresses, server, explicit);
        if (decision.addresses.length > 0) {
          if ((options as dns.LookupAllOptions)?.all) {
            callback(null, decision.addresses.map((a) => ({ address: a, family: 4 })), undefined);
          } else {
            callback(null, decision.addresses[0], 4);
          }
          return;
        }
        if (decision.warning) (err as NodeJS.ErrnoException & { peepResolverWarning?: string }).peepResolverWarning = decision.warning;
        callback(err, address, family);
      });
    });
  }) as typeof dns.lookup;
}

/** Restore the real dns.lookup(). Test-only — production is a one-shot CLI
 *  process that never needs to uninstall. */
export function resetDnsOverrideForTests(): void {
  dns.lookup = REAL_LOOKUP;
  installed = false;
}

/**
 * Append a resolver disagreement warning (if any) to an error's message so it
 * survives being reduced to `.message` in `result.errors`. Checks `err.cause`
 * too: fetch() wraps a dns.lookup() ENOTFOUND in `TypeError: fetch failed`
 * with the real error (and our peepResolverWarning) as `.cause`, so the
 * warning would otherwise never surface for the http scanner.
 */
export function withResolverWarning<E extends Error>(err: E): E {
  const direct = (err as Error & { peepResolverWarning?: string }).peepResolverWarning;
  const causeWarning = (err.cause as (Error & { peepResolverWarning?: string }) | undefined)?.peepResolverWarning;
  const warning = direct ?? causeWarning;
  if (warning) err.message = `${err.message} — ${warning}`;
  return err;
}
