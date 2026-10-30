// Transport layer for talking to the UniFi controller.
// The real transport uses undici with the API key header; the tests' simulated console
// (server/testing/fakeConsole.ts) answers the exact same requests in-process.

import { createHash, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';
import { Agent, buildConnector, request } from 'undici';
import type { CertInfo } from '../../shared/types.ts';

export interface HttpRequest {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  query?: Record<string, string | number | boolean | undefined>;
  body?: unknown;
  timeoutMs?: number;
}

export interface HttpResponse {
  status: number;
  json: unknown;
  text: string;
}

export interface Transport {
  send(req: HttpRequest): Promise<HttpResponse>;
  close(): Promise<void>;
}

export class UniFiHttpError extends Error {
  readonly status: number;
  readonly path: string;
  readonly body: string;

  constructor(status: number, path: string, body: string, message?: string) {
    super(message ?? `UniFi API ${status} for ${path}${body ? `: ${body.slice(0, 300)}` : ''}`);
    this.status = status;
    this.path = path;
    this.body = body;
  }
}

// ---------------------------------------------------------------------------------
// Certificate pinning: a console with its own self-signed certificate can't be checked against a
// certificate authority, so the app remembers that certificate's key the first time and refuses any
// other one afterwards. The check runs right after the TLS handshake, before a request (and so the
// API key) is ever sent.
// ---------------------------------------------------------------------------------

/** What the app pins (the SHA-256 of the public key) and what a person compares (the certificate fingerprint). */
export function certInfo(der: Buffer): CertInfo {
  const x = new X509Certificate(der);
  const spki = createHash('sha256').update(x.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  let selfSigned = false;
  try {
    selfSigned = x.checkIssued(x) && x.verify(x.publicKey);
  } catch {
    selfSigned = false;
  }
  return { spki, sha256: x.fingerprint256, subject: x.subject.replace(/\n/g, ', '), issuer: x.issuer.replace(/\n/g, ', '), validTo: x.validTo, selfSigned };
}

export class TlsPinError extends Error {
  /** The certificate the server presented instead of the trusted one. */
  readonly presented: CertInfo | null;

  constructor(message: string, presented: CertInfo | null) {
    super(message);
    this.name = 'TlsPinError';
    this.presented = presented;
  }
}

/** The certificate a console presents, read from the TLS handshake alone: no request is sent, so no API key either. */
export function fetchCert(baseUrl: string, timeoutMs = 10_000): Promise<CertInfo> {
  const u = new URL(baseUrl);
  const host = u.hostname.replace(/^\[|\]$/g, '');
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({ host, port: Number(u.port) || 443, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const peer = socket.getPeerCertificate(true);
      socket.end();
      try {
        if (!peer?.raw) throw new Error('The console did not present a certificate.');
        resolve(certInfo(peer.raw));
      } catch (e) {
        reject(e);
      }
    });
    socket.on('error', (e) => reject(new Error(`Could not read the certificate of ${u.host}: ${e.message}`)));
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`Timed out reading the certificate of ${u.host}.`));
    });
  });
}

export function buildQuery(query?: HttpRequest['query']): string {
  if (!query) return '';
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined) params.set(k, String(v));
  const s = params.toString();
  return s ? `?${s}` : '';
}

export interface HttpTransportOptions {
  baseUrl: string;
  apiKey: string;
  /** Check the certificate against the public certificate authorities (consoles with a real certificate). */
  verifyTls: boolean;
  /** Otherwise (https only): the trusted key (CertInfo.spki); any other certificate is refused before a request is sent. */
  pin?: string | null;
  /** With no pin yet, trust the first certificate seen and report it so it can be saved. */
  trustOnFirstUse?: boolean;
  onTrust?: (cert: CertInfo) => void;
}

export class HttpTransport implements Transport {
  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly agent: Agent;
  private pin: string | null;
  /** The certificate of the last TLS connection, and the last one refused because it was not the pinned one. */
  seen: CertInfo | null = null;
  mismatch: CertInfo | null = null;

  constructor(opts: HttpTransportOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, '');
    this.apiKey = opts.apiKey;
    this.pin = opts.pin ?? null;
    const pinning = this.baseUrl.startsWith('https://') && !opts.verifyTls;
    // Without a session cache every connection does a full handshake, so the certificate is always there to check.
    const base = buildConnector({ rejectUnauthorized: opts.verifyTls, timeout: 10_000, ...(pinning ? { maxCachedSessions: 0 } : {}) });
    const connect: buildConnector.connector = pinning
      ? (options, callback) =>
          base(options, (err, socket) => {
            if (err || !socket) return callback(err ?? new Error('TLS connection failed'), null);
            let cert: CertInfo | null = null;
            try {
              const peer = (socket as TLSSocket).getPeerCertificate(true);
              cert = peer?.raw ? certInfo(peer.raw) : null;
            } catch {
              cert = null;
            }
            this.seen = cert;
            if (!cert) {
              socket.destroy();
              return callback(new TlsPinError('The console did not present a readable certificate.', null), null);
            }
            if (this.pin && cert.spki !== this.pin) {
              this.mismatch = cert;
              socket.destroy();
              return callback(new TlsPinError('certificate changed', cert), null);
            }
            if (!this.pin && opts.trustOnFirstUse) {
              this.pin = cert.spki;
              opts.onTrust?.(cert);
            }
            this.mismatch = null;
            callback(null, socket);
          })
      : base;
    this.agent = new Agent({
      connect,
      headersTimeout: 20_000,
      bodyTimeout: 60_000,
      keepAliveTimeout: 30_000,
    });
  }

  async send(req: HttpRequest): Promise<HttpResponse> {
    const url = `${this.baseUrl}${req.path}${buildQuery(req.query)}`;
    const headers: Record<string, string> = { 'X-API-KEY': this.apiKey, Accept: 'application/json' };
    let body: string | undefined;
    if (req.body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(req.body);
    }
    let res;
    try {
      res = await request(url, {
        method: req.method,
        headers,
        body,
        dispatcher: this.agent,
        signal: AbortSignal.timeout(req.timeoutMs ?? 30_000),
      });
    } catch (e) {
      const err = e as Error & { code?: string; cause?: { code?: string } };
      if (err instanceof TlsPinError || err.cause instanceof TlsPinError || this.mismatch) {
        throw new UniFiHttpError(
          0,
          req.path,
          '',
          `Refused to connect to ${this.baseUrl}: its certificate is not the one this app trusted, so the API key was not sent. If you replaced the console's certificate or reset the console, review the new one in Settings → Environments. If not, someone may be intercepting the connection.`,
        );
      }
      const code = err.code ?? err.cause?.code ?? '';
      let hint = err.message;
      if (/CERT|SELF_SIGNED|UNABLE_TO_VERIFY/i.test(code + hint)) hint = 'TLS certificate not trusted by a certificate authority. For a console with its own self-signed certificate, turn off "Check the certificate with a certificate authority": the app then trusts that one certificate.';
      else if (/ECONNREFUSED/.test(code)) hint = 'Connection refused - check the URL and port.';
      else if (/ENOTFOUND|EAI_AGAIN/.test(code)) hint = 'Host not found - check the URL.';
      else if (/ETIMEDOUT|UND_ERR_CONNECT_TIMEOUT|TimeoutError|aborted/i.test(code + hint)) hint = 'Timed out connecting to the controller.';
      throw new UniFiHttpError(0, req.path, '', `Cannot reach ${this.baseUrl}: ${hint}`);
    }
    const text = await res.body.text();
    let json: unknown = null;
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = null;
      }
    }
    return { status: res.statusCode, json, text };
  }

  async close(): Promise<void> {
    await this.agent.close();
  }
}
