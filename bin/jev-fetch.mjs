#!/usr/bin/env node
// A `fetchCommand` for networks whose TLS-inspection proxy signs with a CA certificate that names
// anyExtendedKeyUsage instead of serverAuth, which Node and Bun refuse with INVALID_PURPOSE.
// Reads one request as JSON on stdin ({ url, method, headers, body }), sends it to the Jev origin
// only, and prints { status, text } as JSON. On a failure it prints the reason to stderr and exits 1.
// Needs Node 22.15 or later. The measured chain behind it: docs/juice/tls-inspection-proxy.md.
//
// The server gets no byte of the request until one of these holds:
// - Node's own checks pass, name included, against Node's CAs plus the system's.
// - Node's one complaint is INVALID_PURPOSE, and `chainProblem` finds nothing.
// Node keeps the last failed check only, so INVALID_PURPOSE can hide an earlier one
// (an unknown issuer, for example); `chainProblem` repeats those checks by hand.
import { X509Certificate } from 'node:crypto';
import { realpathSync } from 'node:fs';
import https from 'node:https';
import tls from 'node:tls';
import { pathToFileURL } from 'node:url';

export const JEV_ORIGIN = 'https://api.typesafe.ai';
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const ANY_EKU = '2.5.29.37.0';

function signs(child, parent) {
  try {
    return child.checkIssued(parent) && child.verify(parent.publicKey);
  } catch {
    return false;
  }
}

/**
 * Checks the certificates the server sent (leaf first) against the trusted CAs: the name, a
 * signature path to a self-signed trusted CA, the dates, the CA flags, and serverAuth (or no
 * purpose limit) on every certificate except the leaf's issuer, which may name
 * anyExtendedKeyUsage instead. Returns the first failure, or undefined when all pass.
 */
export function chainProblem(sent, trusted, host, now = new Date()) {
  const [leaf] = sent;
  if (!leaf) return 'the server sent no certificate';
  if (tls.checkServerIdentity(host, leaf.toLegacyObject())) return 'the certificate name does not match';
  const pool = [...trusted, ...sent];
  const chain = [leaf];
  for (let cert = pool.find((p) => signs(leaf, p)); cert && !chain.includes(cert); ) {
    chain.push(cert);
    cert = pool.find((p) => signs(cert, p));
  }
  const top = chain.at(-1);
  if (chain.length < 2 || !trusted.includes(top) || !signs(top, top)) return 'the chain does not reach a trusted CA';
  if (!chain.every((cert) => new Date(cert.validFrom) <= now && now <= new Date(cert.validTo))) {
    return 'a certificate is outside its dates';
  }
  if (leaf.ca || !chain.slice(1).every((cert) => cert.ca)) return 'a certificate has the wrong CA flag';
  const purposeOk = (cert, index) =>
    !cert.keyUsage || cert.keyUsage.includes(SERVER_AUTH) || (index === 1 && cert.keyUsage.includes(ANY_EKU));
  if (!chain.every(purposeOk)) return 'a certificate is not for TLS servers';
  return undefined;
}

/** Sends one request to `origin` over a socket cleared as above; resolves `{ status, text }`. */
export function send(request, { ca, origin = JEV_ORIGIN }) {
  const url = new URL(request.url);
  if (url.origin !== origin) return Promise.reject(new Error(`only ${origin} is allowed`));
  const trusted = ca.map((pem) => new X509Certificate(pem));
  // Hands the socket to https only after the checks, so a refused server gets nothing.
  const createConnection = (_options, done) => {
    const socket = tls.connect({
      host: url.hostname,
      port: Number(url.port) || 443,
      servername: url.hostname,
      ca,
      rejectUnauthorized: false,
    });
    socket.once('error', done);
    socket.once('secureConnect', () => {
      const sent = [];
      for (let c = socket.getPeerCertificate(true); c?.raw && !sent.some((s) => s.raw.equals(c.raw)); c = c.issuerCertificate) {
        sent.push(new X509Certificate(c.raw));
      }
      const problem = socket.authorized
        ? undefined
        : socket.authorizationError === 'INVALID_PURPOSE'
          ? chainProblem(sent, trusted, url.hostname)
          : `TLS check failed: ${socket.authorizationError}`;
      if (!problem) return done(null, socket);
      socket.destroy();
      done(new Error(`refused ${url.hostname}: ${problem}`));
    });
  };
  return new Promise((resolve, reject) => {
    const req = https.request(
      url,
      { method: request.method ?? 'GET', headers: request.headers, defaultPort: 443, createConnection },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (text += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text }));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end(request.body);
  });
}

async function main() {
  if (typeof tls.getCACertificates !== 'function') throw new Error('needs Node 22.15 or later');
  let input = '';
  for await (const chunk of process.stdin) input += chunk;
  let request;
  try {
    request = JSON.parse(input);
  } catch {
    throw new Error('stdin is not a JSON request'); // JSON.parse would quote the input, key included
  }
  const ca = [...new Set([...tls.getCACertificates('default'), ...tls.getCACertificates('system')])];
  process.stdout.write(JSON.stringify(await send(request, { ca })));
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`jev-fetch: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
