import { promises as dns } from 'node:dns';
import type { DnsResult, SpfRecord, DmarcRecord } from '../types.js';

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

/** Common DKIM selectors worth probing — most senders use one of these rather
 *  than a domain-specific value, so a positive hit is cheap to find. */
export const DKIM_SELECTORS = ['default', 'google', 'resend', 'zoho', 'k1', 'selector1', 'selector2', 'mail', 'dkim', 's1', 's2', 'mandrill', 'mailjet', 'protonmail'];

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
    spf: null,
    dmarc: null,
    caa: [],
    dkim: [],
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
    // DMARC lives on its own label; a missing record is the common case, not an error.
    client.resolveTxt(`_dmarc.${domain}`).then((r) => {
      const rec = r.map((t) => t.join('')).find((t) => /^v=dmarc1\b/i.test(t.trim()));
      if (rec) result.dmarc = parseDmarc(rec);
    }).catch(() => {}),
    client.resolveCaa(domain).then((r) => {
      result.caa = r.map(formatCaa).filter((s): s is string => s !== null);
    }).catch(() => {}),
    ...DKIM_SELECTORS.map((selector) =>
      client.resolveTxt(`${selector}._domainkey.${domain}`).then((r) => {
        // p= must carry an actual key — a wildcard/parked-domain TXT record
        // (some registrars answer any `*._domainkey` query) or a revoked key
        // both present as `v=DKIM1; p=` with nothing after `p=`, and must not
        // read as "DKIM configured".
        const raw = r.map((t) => t.join('')).find((t) => /v=dkim1\b/i.test(t) && /p=[a-z0-9+/]/i.test(t));
        if (raw) result.dkim!.push({ selector, raw });
      }).catch(() => {})),
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

  const spfTxt = result.txt.find((t) => /^v=spf1\b/i.test(t.trim()));
  if (spfTxt) result.spf = parseSpf(spfTxt);

  return result;
}

/** Parse a `v=spf1 …` TXT record into its mechanisms. Exported for tests. */
export function parseSpf(raw: string): SpfRecord {
  const rec: SpfRecord = { raw, includes: [], ip4: [], ip6: [], redirect: null, all: null };
  for (const term of raw.trim().split(/\s+/).slice(1)) {
    const lower = term.toLowerCase();
    // Strip an optional qualifier (+ - ~ ?) for mechanism matching
    const bare = lower.replace(/^[+\-~?]/, '');
    if (bare.startsWith('include:')) rec.includes.push(bare.slice(8));
    else if (bare.startsWith('ip4:')) rec.ip4.push(bare.slice(4));
    else if (bare.startsWith('ip6:')) rec.ip6.push(bare.slice(4));
    else if (bare.startsWith('redirect=')) rec.redirect = bare.slice(9);
    else if (bare === 'all') {
      const q = lower[0];
      rec.all = q === '-' ? '-all' : q === '~' ? '~all' : q === '?' ? '?all' : '+all';
    }
  }
  return rec;
}

/** Parse a `v=DMARC1; p=…; rua=…` record. Exported for tests. */
export function parseDmarc(raw: string): DmarcRecord {
  const rec: DmarcRecord = { raw, policy: null, subdomainPolicy: null, rua: [], ruf: [], pct: null };
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim();
    if (!value) continue;
    switch (key) {
      case 'p': rec.policy = value.toLowerCase(); break;
      case 'sp': rec.subdomainPolicy = value.toLowerCase(); break;
      case 'pct': { const n = parseInt(value, 10); if (!Number.isNaN(n)) rec.pct = n; break; }
      case 'rua': rec.rua = parseReportUris(value); break;
      case 'ruf': rec.ruf = parseReportUris(value); break;
    }
  }
  return rec;
}

/** `mailto:a@x.com!10m,mailto:b@y.com` → ['a@x.com', 'b@y.com'] (lowercased). */
function parseReportUris(value: string): string[] {
  const out: string[] = [];
  for (const uri of value.split(',')) {
    const addr = uri.trim().replace(/^mailto:/i, '').replace(/![^,]*$/, '').toLowerCase();
    if (addr && !out.includes(addr)) out.push(addr);
  }
  return out;
}

function formatCaa(rec: { critical: number; issue?: string; issuewild?: string; iodef?: string; contactemail?: string; contactphone?: string }): string | null {
  for (const tag of ['issue', 'issuewild', 'iodef', 'contactemail', 'contactphone'] as const) {
    const value = (rec as Record<string, unknown>)[tag];
    if (typeof value === 'string' && value) return `${tag} ${value}`;
  }
  return null;
}
