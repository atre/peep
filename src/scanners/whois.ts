import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { WhoisResult } from '../types.js';

const execFileAsync = promisify(execFile);

// TLD → WHOIS server fallback for registries that don't set a refer: field in IANA
const WHOIS_SERVERS: Record<string, string> = {
  io: 'whois.nic.io',
  me: 'whois.nic.me',
  co: 'whois.nic.co',
  ai: 'whois.nic.ai',
  sh: 'whois.nic.sh',
  to: 'whois.tonic.to',
  cc: 'ccwhois.verisign-grs.com',
  tv: 'tvwhois.verisign-grs.com',
};

// TLDs that use RDAP instead of WHOIS — bootstrap via rdap.org redirects to the right server
const RDAP_BOOTSTRAP = 'https://rdap.org/domain/';

// TLDs known to have no WHOIS server (RDAP-only)
const RDAP_ONLY_TLDS = new Set([
  'dev', 'app', 'page', 'new', 'day', 'how', 'soy', 'foo', 'zip', 'mov', 'nexus',
]);

export async function scanWhois(domain: string): Promise<WhoisResult> {
  const tld = domain.split('.').pop()?.toLowerCase() ?? '';
  const reasons: string[] = [];

  // Try traditional WHOIS first
  let raw: string;
  try {
    raw = await queryWhois(domain);
  } catch (e) {
    raw = '';
    reasons.push(whoisFailureReason(e));
  }

  let parsed = parseWhois(raw);

  // If we only got TLD-level data, try fallback approaches
  if (!parsed.registrar && !parsed.createdDate) {
    // Try refer: field
    const refer = extract(raw, /refer:\s*(\S+)/i);
    const server = refer || WHOIS_SERVERS[tld];

    if (server) {
      try {
        const followUp = await queryWhois(domain, server);
        const followParsed = parseWhois(followUp);
        if (followParsed.registrar || followParsed.createdDate) {
          raw = followUp;
          return withExpiresIn({ ...followParsed, raw });
        }
        reasons.push(`refer follow-up to ${server} returned no registrar/created date`);
      } catch (e) {
        reasons.push(`refer follow-up to ${server} failed: ${(e as Error).message}`);
      }
    }

    // Try RDAP for TLDs that don't have WHOIS (e.g. .dev, .app)
    if (RDAP_ONLY_TLDS.has(tld) || !parsed.registrar) {
      try {
        const rdapResult = await queryRdap(RDAP_BOOTSTRAP, domain);
        if (rdapResult.registrar || rdapResult.createdDate) {
          return withExpiresIn({ ...rdapResult, raw: rdapResult.raw || raw });
        }
        reasons.push('RDAP returned no registrar/created date');
      } catch (e) {
        reasons.push((e as Error).message);
      }
    }
  }

  if (!parsed.registrar && !parsed.createdDate) {
    throw new Error(`unavailable: ${reasons.length ? reasons.join('; ') : 'no registrar/created date found'}`);
  }

  return withExpiresIn({ ...parsed, raw });
}

/** Attach `expiresIn` (days until `expiryDate`, negative = expired) — computed
 *  once here rather than left to every consumer to parse the date string.
 *  Exported for tests; scanWhois itself does real I/O and isn't unit-testable. */
export function withExpiresIn(result: WhoisResult): WhoisResult {
  if (!result.expiryDate) return { ...result, expiresIn: null };
  const t = Date.parse(result.expiryDate);
  return { ...result, expiresIn: Number.isNaN(t) ? null : Math.floor((t - Date.now()) / 86_400_000) };
}

function whoisFailureReason(e: unknown): string {
  const err = e as NodeJS.ErrnoException;
  if (err?.code === 'ENOENT') return 'whois binary not found';
  if (err?.name === 'AbortError' || /timed?\s*out/i.test(err?.message ?? '')) return 'whois query timed out';
  return `whois query failed: ${err?.message ?? 'unknown error'}`;
}

// Strict domain validation — prevents flag injection and malformed input
const VALID_DOMAIN_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i;
const VALID_HOSTNAME_RE = /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i;

async function queryWhois(domain: string, server?: string): Promise<string> {
  if (!VALID_DOMAIN_RE.test(domain)) throw new Error(`Invalid domain for WHOIS: ${domain}`);
  if (server && !VALID_HOSTNAME_RE.test(server)) throw new Error(`Invalid WHOIS server: ${server}`);
  const args = server ? ['-h', server, domain] : [domain];
  const { stdout } = await execFileAsync('whois', args, {
    encoding: 'utf-8',
    timeout: 15000,
    maxBuffer: 1024 * 1024,
  });
  return stdout;
}

async function queryRdap(baseUrl: string, domain: string): Promise<WhoisResult> {
  if (!VALID_DOMAIN_RE.test(domain)) throw new Error(`Invalid domain for RDAP: ${domain}`);
  const url = `${baseUrl}${encodeURIComponent(domain)}`;
  const resp = await fetch(url, {
    headers: { Accept: 'application/rdap+json' },
    redirect: 'follow',
    signal: AbortSignal.timeout(10000),
  });

  if (!resp.ok) {
    throw new Error(`RDAP query failed: ${resp.status}`);
  }

  const data = await resp.json() as RdapResponse;
  const raw = JSON.stringify(data, null, 2);

  // Extract registrar from entities
  let registrar: string | null = null;
  if (data.entities) {
    const registrarEntity = data.entities.find((e) =>
      e.roles?.includes('registrar'));
    if (registrarEntity) {
      registrar = registrarEntity.vcardArray?.[1]
        ?.find((v: unknown[]) => v[0] === 'fn')?.[3] as string
        ?? registrarEntity.handle
        ?? null;
    }
  }

  // Extract dates from events
  let createdDate: string | null = null;
  let updatedDate: string | null = null;
  let expiryDate: string | null = null;
  if (data.events) {
    for (const event of data.events) {
      if (event.eventAction === 'registration') createdDate = event.eventDate;
      else if (event.eventAction === 'last changed') updatedDate = event.eventDate;
      else if (event.eventAction === 'expiration') expiryDate = event.eventDate;
    }
  }

  // Extract nameservers — dedupe: some RDAP responses list the same host under
  // more than one nameserver object (e.g. glue + delegation records).
  const nameservers: string[] = [];
  const seenNs = new Set<string>();
  if (data.nameservers) {
    for (const ns of data.nameservers) {
      const host = ns.ldhName?.toLowerCase();
      if (host && !seenNs.has(host)) {
        seenNs.add(host);
        nameservers.push(host);
      }
    }
  }

  // Extract DNSSEC status
  let dnssec: string | null = null;
  if (data.secureDNS) {
    dnssec = data.secureDNS.delegationSigned ? 'signed' : 'unsigned';
  }

  // Extract registrant from entities
  let registrantOrg: string | null = null;
  let registrantCountry: string | null = null;
  if (data.entities) {
    const registrantEntity = data.entities.find((e) =>
      e.roles?.includes('registrant'));
    if (registrantEntity) {
      const vcard = registrantEntity.vcardArray?.[1];
      if (vcard) {
        registrantOrg = (vcard.find((v: unknown[]) => v[0] === 'org')?.[3] as string)
          ?? (vcard.find((v: unknown[]) => v[0] === 'fn')?.[3] as string)
          ?? null;
        // Country from adr field: adr value is [pobox, ext, street, city, region, postalCode, country]
        const adr = vcard.find((v: unknown[]) => v[0] === 'adr');
        if (adr) {
          const adrValue = adr[3];
          if (Array.isArray(adrValue) && adrValue.length >= 7) {
            registrantCountry = (adrValue[6] as string) || null;
          }
        }
      }
    }
  }

  return {
    registrar,
    createdDate,
    updatedDate,
    expiryDate,
    nameservers,
    registrantOrg,
    registrantCountry,
    dnssec,
    raw,
  };
}

interface RdapResponse {
  handle?: string;
  ldhName?: string;
  entities?: Array<{
    handle?: string;
    roles?: string[];
    vcardArray?: [string, unknown[][]];
  }>;
  events?: Array<{
    eventAction: string;
    eventDate: string;
  }>;
  nameservers?: Array<{
    ldhName?: string;
  }>;
  secureDNS?: {
    delegationSigned?: boolean;
  };
}

function parseWhois(raw: string): Omit<WhoisResult, 'raw'> {
  return {
    registrar: extract(raw, /Registrar:\s*(.+)/i) ?? extract(raw, /Sponsoring Registrar:\s*(.+)/i),
    createdDate: extract(raw, /Creation Date:\s*(.+)/i) ?? extract(raw, /Created Date:\s*(.+)/i) ?? extract(raw, /Registration Date:\s*(.+)/i),
    updatedDate: extract(raw, /Updated Date:\s*(.+)/i) ?? extract(raw, /Last Updated:\s*(.+)/i),
    expiryDate: extract(raw, /Expir(?:y|ation) Date:\s*(.+)/i) ?? extract(raw, /Registry Expiry Date:\s*(.+)/i),
    // Some registries repeat Name Server lines across registry/registrar sections
    // of the same response — dedupe so downstream output doesn't show doubles.
    nameservers: [...new Set(extractAll(raw, /Name Server:\s*(.+)/gi).map((s) => s.trim().toLowerCase()))],
    registrantOrg: extract(raw, /Registrant Organization:\s*(.+)/i),
    registrantCountry: extract(raw, /Registrant Country:\s*(.+)/i),
    dnssec: extract(raw, /DNSSEC:\s*(.+)/i),
  };
}

function extract(text: string, pattern: RegExp): string | null {
  const match = text.match(pattern);
  return match?.[1]?.trim() ?? null;
}

function extractAll(text: string, pattern: RegExp): string[] {
  const results: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(text)) !== null) {
    if (match[1]) results.push(match[1]);
    if (match[0].length === 0) pattern.lastIndex++;
  }
  return results;
}
