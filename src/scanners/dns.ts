import { promises as dns } from 'node:dns';
import type { DnsResult } from '../types.js';

/**
 * Record-type resolver client: the module-level dns.promises functions (system
 * default nameservers) unless --dns pinned a specific server, in which case a
 * one-off Resolver instance targets exactly that server. Same method names on
 * both, so callers below don't need to branch.
 */
function resolverFor(dnsServer?: string): typeof dns {
  if (!dnsServer) return dns;
  const resolver = new dns.Resolver();
  resolver.setServers([dnsServer]);
  return resolver as unknown as typeof dns;
}

export async function scanDns(domain: string, dnsServer?: string): Promise<DnsResult> {
  const client = resolverFor(dnsServer);
  const result: DnsResult = {
    a: [],
    aaaa: [],
    mx: [],
    txt: [],
    ns: [],
    cname: [],
    googleVerification: null,
    microsoftVerification: null,
    facebookVerification: null,
  };

  const jobs = [
    client.resolve4(domain).then((r) => { result.a = r; }).catch(() => {}),
    client.resolve6(domain).then((r) => { result.aaaa = r; }).catch(() => {}),
    client.resolveMx(domain).then((r) => {
      result.mx = r.map((m) => ({ exchange: m.exchange, priority: m.priority }));
    }).catch(() => {}),
    client.resolveTxt(domain).then((r) => {
      result.txt = r.map((t) => t.join(''));
    }).catch(() => {}),
    client.resolveNs(domain).then((r) => { result.ns = r; }).catch(() => {}),
    client.resolveCname(domain).then((r) => { result.cname = r; }).catch(() => {}),
  ];

  await Promise.all(jobs);

  // Extract specific verification tokens from TXT records
  for (const txt of result.txt) {
    if (!result.googleVerification) {
      const m = txt.match(/^google-site-verification=([A-Za-z0-9_-]+)/i);
      if (m?.[1]) result.googleVerification = m[1];
    }
    if (!result.microsoftVerification) {
      const m = txt.match(/^ms=([A-Za-z0-9_-]+)/i);
      if (m?.[1]) result.microsoftVerification = m[1];
    }
    if (!result.facebookVerification) {
      const m = txt.match(/^facebook-domain-verification=([a-z0-9]+)/i);
      if (m?.[1]) result.facebookVerification = m[1];
    }
  }

  return result;
}
