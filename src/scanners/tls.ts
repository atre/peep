import * as tls from 'node:tls';
import type { TlsResult } from '../types.js';
import { withResolverWarning } from '../resolver.js';

export async function scanTls(domain: string, timeout: number): Promise<TlsResult> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
        timeout,
      },
      () => {
        // Request detailed cert (true = return full chain including SAN/expiry)
        const cert = socket.getPeerCertificate(true);
        const proto = socket.getProtocol();
        const cipher = socket.getCipher();

        // valid_to can be a string date or undefined depending on Node version
        const validTo = cert.valid_to ?? '';
        let daysUntilExpiry: number | null = null;
        if (validTo) {
          const expiryMs = new Date(validTo).getTime();
          if (!isNaN(expiryMs)) {
            daysUntilExpiry = Math.floor((expiryMs - Date.now()) / (1000 * 60 * 60 * 24));
          }
        }

        // subjectaltname may be on the cert directly or accessible as a string
        const sanRaw: string = (cert as any).subjectaltname ?? '';

        const result: TlsResult = {
          issuer: formatDN(cert.issuer),
          subject: formatDN(cert.subject),
          validFrom: cert.valid_from ?? '',
          validTo,
          serialNumber: cert.serialNumber ?? '',
          san: parseSAN(sanRaw),
          protocol: proto ?? '',
          cipher: cipher?.name ?? '',
          fingerprint: cert.fingerprint256 ?? cert.fingerprint ?? '',
          daysUntilExpiry,
        };

        socket.destroy();
        resolve(result);
      },
    );

    socket.on('error', (err) => {
      socket.destroy();
      // tls.connect() resolves hostnames via dns.lookup() internally — same
      // peepResolverWarning fallback as the http scanner (see src/resolver.ts).
      reject(withResolverWarning(err));
    });

    socket.setTimeout(timeout, () => {
      socket.destroy();
      reject(new Error('TLS connection timed out'));
    });
  });
}

function formatDN(dn: Record<string, unknown> | undefined): string {
  if (!dn) return '';
  return Object.entries(dn)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join('+') : String(v)}`)
    .join(', ');
}

function parseSAN(san: string): string[] {
  if (!san) return [];
  return san.split(',').map((s) => s.trim().replace(/^DNS:/, ''));
}
