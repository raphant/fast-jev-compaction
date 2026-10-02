// Question: behind a TLS-inspection proxy, does the Jev chain pass every check except the serverAuth purpose?
// Opens one TLS connection with Node's checks off, runs each check by hand against the system trust store,
// and prints booleans and OIDs only (no certificate names). Sends one keyless GET only if all checks pass.
// Run from the repo root: node .juice/tls-inspection-proxy/skip-only-serverauth/probe.mjs
import tls from 'node:tls';
import { X509Certificate } from 'node:crypto';

const host = 'api.typesafe.ai';
const SERVER_AUTH = '1.3.6.1.5.5.7.3.1';
const store = tls.getCACertificates('system').map((pem) => new X509Certificate(pem));
const tryVerify = (cert, key) => { try { return cert.verify(key); } catch { return false; } };
const signs = (child, parent) => child.checkIssued(parent) && tryVerify(child, parent.publicKey);
const inDate = (cert) => new Date(cert.validFrom) <= new Date() && new Date() <= new Date(cert.validTo);

const socket = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false }, () => {
  const peer = socket.getPeerCertificate(true);
  const sent = [];
  for (let c = peer; c?.raw && !sent.some((s) => s.raw.equals(c.raw)); c = c.issuerCertificate) sent.push(new X509Certificate(c.raw));
  const [leaf] = sent;
  // Leaf, then its issuer from the certs the server sent, then issuers from the system store up to a self-signed CA.
  const chain = [leaf];
  for (let c = sent.find((s) => signs(leaf, s)); c && !chain.includes(c); c = store.find((s) => signs(c, s))) chain.push(c);
  const top = chain.at(-1);
  const other = store.find((s) => !s.publicKey.equals(chain[1]?.publicKey ?? s.publicKey));
  const checks = {
    nodeVerdict: socket.authorizationError ?? 'none',
    storeSize: store.length, sentCount: sent.length, chainLength: chain.length,
    leafNameMatchesHost: tls.checkServerIdentity(host, peer) === undefined,
    nameCheckRejectsOtherHost: tls.checkServerIdentity('example.com', peer) !== undefined,
    signatureCheckRejectsWrongKey: !tryVerify(leaf, other.publicKey),
    anchoredAtSelfSignedStoreCA: chain.length > 1 && store.includes(top) && signs(top, top),
    chainInDate: chain.map(inDate), chainIsCA: chain.map((c) => c.ca), chainEku: chain.map((c) => c.keyUsage ?? 'absent'),
  };
  const leafEkuOk = !leaf.keyUsage || leaf.keyUsage.includes(SERVER_AUTH);
  const pass = checks.leafNameMatchesHost && checks.nameCheckRejectsOtherHost && checks.signatureCheckRejectsWrongKey
    && checks.anchoredAtSelfSignedStoreCA && chain.every(inDate) && !leaf.ca && chain.slice(1).every((c) => c.ca) && leafEkuOk;
  console.log(JSON.stringify({ ...checks, leafEkuOk, allChecksExceptPurposePass: pass }, null, 1));
  if (!pass) return socket.destroy();
  socket.write(`GET /v1/systemone HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
  socket.once('data', (data) => { console.log('keyless GET:', data.toString().split('\r\n')[0]); socket.destroy(); });
});
socket.setTimeout(15000, () => { console.log('timeout'); socket.destroy(); });
socket.on('error', (error) => console.log('error:', error.code ?? error.message));
