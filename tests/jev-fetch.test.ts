import { execFileSync, spawnSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { chainProblem, send } from '../bin/jev-fetch.mjs';

// The certificates are made with the OpenSSL 3 command line, so the suite skips without it.
const hasOpenssl = (() => {
  try {
    return execFileSync('openssl', ['version']).toString().startsWith('OpenSSL 3');
  } catch {
    return false;
  }
})();

const CA = 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\n';
const LEAF = 'basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nsubjectAltName=DNS:localhost\n';
const BODY = '{"questions":{}}';

describe.skipIf(!hasOpenssl)('bin/jev-fetch.mjs', () => {
  let dir = '';
  const pem: Record<string, string> = {};
  const key: Record<string, string> = {};

  /** Makes a P-256 certificate called `name`, signed by `issuer`, or self-signed without one. */
  function makeCert(name: string, ext: string, issuer?: string, dates = ['-days', '3650']) {
    const run = (args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: 'pipe' });
    run(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', `${name}.key`]);
    run(['req', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.csr`]);
    writeFileSync(join(dir, `${name}.ext`), ext);
    const signer = issuer ? ['-CA', `${issuer}.pem`, '-CAkey', `${issuer}.key`] : ['-key', `${name}.key`];
    run(['x509', '-req', '-in', `${name}.csr`, ...signer, ...dates, '-extfile', `${name}.ext`, '-out', `${name}.pem`]);
    pem[name] = readFileSync(join(dir, `${name}.pem`), 'utf8');
    key[name] = readFileSync(join(dir, `${name}.key`), 'utf8');
  }

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'jev-fetch-'));
    makeCert('root', CA);
    makeCert('other', CA);
    // The inspection proxy's shape: a CA that names anyExtendedKeyUsage, not serverAuth.
    makeCert('proxy', `${CA}extendedKeyUsage=anyExtendedKeyUsage\n`, 'root');
    makeCert('leaf', `${LEAF}extendedKeyUsage=serverAuth\n`, 'proxy');
    makeCert('clientLeaf', `${LEAF}extendedKeyUsage=clientAuth\n`, 'proxy');
    makeCert('expired', `${LEAF}extendedKeyUsage=serverAuth\n`, 'proxy', [
      '-not_before', '20200101000000Z', '-not_after', '20200102000000Z',
    ]);
    makeCert('normal', `${CA}extendedKeyUsage=serverAuth\n`, 'root');
    makeCert('normalLeaf', `${LEAF}extendedKeyUsage=serverAuth\n`, 'normal');
    makeCert('mid', `${CA}extendedKeyUsage=anyExtendedKeyUsage\n`, 'root');
    makeCert('sub', CA, 'mid');
    makeCert('deepLeaf', `${LEAF}extendedKeyUsage=serverAuth\n`, 'sub');
    makeCert('narrowRoot', `${CA}nameConstraints=critical,permitted;DNS:example.com\n`);
    makeCert('narrowProxy', `${CA}extendedKeyUsage=anyExtendedKeyUsage\n`, 'narrowRoot');
    makeCert('narrowLeaf', `${LEAF}extendedKeyUsage=serverAuth\n`, 'narrowProxy');
    makeCert('fitRoot', `${CA}nameConstraints=critical,permitted;DNS:localhost\n`);
    makeCert('fitProxy', `${CA}extendedKeyUsage=anyExtendedKeyUsage\n`, 'fitRoot');
    makeCert('fitLeaf', `${LEAF}extendedKeyUsage=serverAuth\n`, 'fitProxy');
  }, 30_000);

  afterAll(() => {
    if (dir) rmSync(dir, { recursive: true, force: true });
  });

  const certs = (...names: string[]) => names.map((name) => new X509Certificate(pem[name]!));

  it('passes a chain whose only flaw is anyExtendedKeyUsage on the leaf issuer', () => {
    expect(chainProblem(certs('leaf', 'proxy'), certs('root'), 'localhost')).toBeUndefined();
  });

  it.each([
    ['a wrong host', ['leaf', 'proxy'], ['root'], 'other.test', 'the certificate name does not match'],
    ['an untrusted root', ['leaf', 'proxy'], ['other'], 'localhost', 'the chain does not reach a trusted CA'],
    ['an expired leaf', ['expired', 'proxy'], ['root'], 'localhost', 'a certificate is outside its dates'],
    ['a leaf without serverAuth', ['clientLeaf', 'proxy'], ['root'], 'localhost', 'a certificate is not for TLS servers'],
    ['anyExtendedKeyUsage above the leaf issuer', ['deepLeaf', 'sub', 'mid'], ['root'], 'localhost', 'a certificate is not for TLS servers'],
  ])('refuses %s', (_case, sent, trusted, host, problem) => {
    expect(chainProblem(certs(...sent), certs(...trusted), host)).toBe(problem);
  });

  /** A TLS server on 127.0.0.1 that records every byte and answers once the body has arrived. */
  function serve(chain: string, keyPem: string) {
    const received: string[] = [];
    const server = tls.createServer({ key: keyPem, cert: chain }, (socket) => {
      socket.on('error', () => {});
      socket.on('data', (data) => {
        received.push(data.toString());
        if (received.join('').endsWith(BODY)) {
          socket.end('HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{"ok":true}');
        }
      });
    });
    server.on('tlsClientError', () => {});
    return new Promise<{ origin: string; received: string[]; close: () => void }>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const { port } = server.address() as AddressInfo;
        resolve({ origin: `https://localhost:${port}`, received, close: () => server.close() });
      });
    });
  }

  const request = (origin: string) => ({
    url: `${origin}/v1/systemone`,
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: BODY,
  });

  it.each([
    ['the proxy chain, which Node refuses with INVALID_PURPOSE', 'leaf', 'proxy', 'root'],
    ['a normal chain, which Node accepts', 'normalLeaf', 'normal', 'root'],
    ['a proxy chain under a name constraint it meets', 'fitLeaf', 'fitProxy', 'fitRoot'],
  ])('sends the request through %s', async (_case, leaf, issuer, root) => {
    const server = await serve(pem[leaf]! + pem[issuer]!, key[leaf]!);
    try {
      const out = await send(request(server.origin), { ca: [pem[root]!], origin: server.origin });
      expect(out).toEqual({ status: 200, text: '{"ok":true}' });
      expect(server.received.join('')).toMatch(/^POST \/v1\/systemone HTTP\/1\.1\r\n/);
    } finally {
      server.close();
    }
  });

  it('sends no byte to a server it refuses, even when Node reports only INVALID_PURPOSE', async () => {
    const server = await serve(pem.leaf! + pem.proxy!, key.leaf!);
    try {
      // Node keeps the last failed check, so the unknown root hides behind INVALID_PURPOSE.
      await expect(send(request(server.origin), { ca: [pem.other!], origin: server.origin })).rejects.toThrow(
        'refused localhost: the chain does not reach a trusted CA',
      );
      expect(server.received).toEqual([]);
    } finally {
      server.close();
    }
  });

  it('refuses a name outside a CA name constraint, which Node reports instead of INVALID_PURPOSE', async () => {
    const server = await serve(pem.narrowLeaf! + pem.narrowProxy!, key.narrowLeaf!);
    try {
      // chainProblem does not read name constraints; Node reports the violation as UNSPECIFIED.
      await expect(send(request(server.origin), { ca: [pem.narrowRoot!], origin: server.origin })).rejects.toThrow(
        'refused localhost: TLS check failed: UNSPECIFIED',
      );
      expect(server.received).toEqual([]);
    } finally {
      server.close();
    }
  });

  it('never repeats its input on stderr', () => {
    const run = (input: string) =>
      spawnSync(process.execPath, ['bin/jev-fetch.mjs'], { input, encoding: 'utf8' });
    const broken = run('{"headers":{"authorization":"Bearer secret-key"');
    expect(broken.status).toBe(1);
    expect(broken.stderr).toBe('jev-fetch: stdin is not a JSON request\n');
    const elsewhere = run('{"url":"https://example.com/","headers":{"authorization":"Bearer secret-key"}}');
    expect(elsewhere.stderr).toBe('jev-fetch: only https://api.typesafe.ai is allowed\n');
  });

  it('refuses every origin but the one it serves, before it connects', async () => {
    await expect(send({ url: 'https://example.com/v1/systemone' }, { ca: [] })).rejects.toThrow(
      'only https://api.typesafe.ai is allowed',
    );
  });
});
