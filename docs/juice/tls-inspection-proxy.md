# TLS-inspection proxy

Measured facts about Jev calls on a network with a TLS-inspection proxy: a proxy that decrypts TLS and signs a new certificate for each host.
Newest entry first.

### Node's authorizationError keeps the last failed check, so INVALID_PURPOSE can hide an unknown root

Last verified 2026-10-02 — Node v22.19.0, test certificates made with OpenSSL 3.6.3
Re-run: `npx vitest run tests/jev-fetch.test.ts`

The tests serve a leaf and a proxy CA that names only anyExtendedKeyUsage from a TLS server on 127.0.0.1, and connect through `bin/jev-fetch.mjs` with `rejectUnauthorized: false`.
Expected an unknown root to show as an issuer error. Got, with a trusted CA list that does not hold the root:

    refused localhost: the chain does not reach a trusted CA

That message comes only from `chainProblem`, which runs only when `authorizationError` is `INVALID_PURPOSE`. With a root whose name constraint permits only `example.com`:

    refused localhost: TLS check failed: UNSPECIFIED

So: never accept a chain on `authorizationError === 'INVALID_PURPOSE'` alone; repeat the chain checks by hand. A name-constraint failure comes out as `UNSPECIFIED`, not `INVALID_PURPOSE`, so the helper refuses it without a check of its own.

### The Jev chain behind a TLS-inspection proxy fails only the proxy certificate's serverAuth purpose

Last verified 2026-10-02 — Node v22.19.0, Darwin 25.6.0, a network with a TLS-inspection proxy
Re-run: `node .juice/tls-inspection-proxy/skip-only-serverauth/probe.mjs`

The probe opened one TLS connection to `api.typesafe.ai:443` with `rejectUnauthorized: false`.
Then it ran each check by hand against `tls.getCACertificates('system')`.
The chain arrays are in this order: the leaf, the proxy certificate, then two CAs from the system store.
Expected the proxy certificate to fail the purpose check, and every other check to pass. Got:

    {
     "nodeVerdict": "INVALID_PURPOSE",
     "storeSize": 13,
     "sentCount": 4,
     "chainLength": 4,
     "leafNameMatchesHost": true,
     "nameCheckRejectsOtherHost": true,
     "signatureCheckRejectsWrongKey": true,
     "anchoredAtSelfSignedStoreCA": true,
     "chainInDate": [
      true,
      true,
      true,
      true
     ],
     "chainIsCA": [
      false,
      true,
      true,
      true
     ],
     "chainEku": [
      [
       "1.3.6.1.5.5.7.3.1"
      ],
      [
       "2.5.29.37.0"
      ],
      "absent",
      "absent"
     ],
     "leafEkuOk": true,
     "allChecksExceptPurposePass": true
    }
    keyless GET: HTTP/1.1 405 Method Not Allowed

`1.3.6.1.5.5.7.3.1` is serverAuth. `2.5.29.37.0` is anyExtendedKeyUsage, which OpenSSL and BoringSSL do not accept as serverAuth.

So:

- A Node helper can trust this chain only if it runs every check by hand and skips the purpose check on the proxy certificate alone. Every other certificate passes that check. `bin/jev-fetch.mjs` is that helper.
- The system store holds the full path to a self-signed CA, so the helper needs no pinned CA file.
- Do not use `authorizationError` to decide trust. This connection used Node's bundled CA list (`NODE_EXTRA_CA_CERTS` and `NODE_USE_SYSTEM_CA` unset), which holds public CAs only. Node still reported `INVALID_PURPOSE`, not an issuer error, because Node lets every check run and keeps the last failure.
- HTTP works over the checked socket. The keyless GET got 405 because the endpoint takes POST.
- The probe did not check revocation, name constraints, or key strength.
