# Comparison: http-fields-signatures vs http-message-signatures

The most established alternative on npm is
[`http-message-signatures`](https://github.com/dhensby/node-http-message-signatures)
(dhensby). Both libraries implement HTTP Message Signatures; here is how they
differ, and how to do the same tasks in each.

There's a neat symmetry in the stacks: `http-message-signatures` builds on
[`structured-headers`](https://github.com/badgateway/structured-headers)
(badgateway) for its Structured Field Values, while this library builds on
[`http-fields`](https://github.com/johnhenry/http-fields) — the same pairing
compared in http-fields' own
[COMPARISON.md](https://github.com/johnhenry/http-fields/blob/main/COMPARISON.md).

## At a glance

| | http-fields-signatures | http-message-signatures |
| --- | --- | --- |
| **Spec target** | RFC 9421 (final) | draft-ietf-httpbis-message-signatures-13 (per its README), plus the legacy Cavage draft |
| **Legacy Cavage support** | No | Yes (`draft-cavage-http-signatures`) |
| **Crypto engine** | WebCrypto (`globalThis.crypto.subtle`) | Node `crypto` built-ins; pluggable signer/verifier interface |
| **Runtimes** | Node ≥ 20, browsers, edge workers | Node-first (custom signers can bridge elsewhere) |
| **Bring-your-own-signer (KMS/enclave)** | Not yet — keys must be importable material | Yes: any `{id, alg, sign(data)}` object |
| **Key formats** | CryptoKey, JWK, PEM (PKCS#8 / SPKI / SEC1 via built-in transcoding), raw bytes (HMAC) | Node `KeyObject`-compatible inputs via `createSigner`/`createVerifier`, or custom signer |
| **SFV engine** | http-fields | structured-headers (badgateway) |
| **Conformance testing** | Full RFC 9421 Appendix B vectors: all six signature bases byte-exact; RFC signatures verified; HMAC/Ed25519 byte-exact | Own test suite |
| **Verify failure style** | Per-label result objects: `{verified, reason}`; structural errors throw | `verifyMessage` throws (e.g. on missing key) |
| **Signing output** | Header values to attach (`{signatureInput, signature, base}`) | The whole message object with headers added |
| **Dependencies** | http-fields | structured-headers |

## Same task, both libraries

### Signing a request

**http-fields-signatures:**

```javascript
import { signMessage } from "http-fields-signatures";

const request = {
  method: "POST",
  url: "https://example.com/foo",
  headers: { "Content-Type": "application/json" },
};

const { signatureInput, signature } = await signMessage(request, {
  alg: "hmac-sha256",
  key: secretBytes, // Uint8Array; or JWK/PEM/CryptoKey for asymmetric algs
  keyid: "my-key-id",
  components: ["@method", "@authority", "content-type"],
});
request.headers["Signature-Input"] = signatureInput;
request.headers["Signature"] = signature;
```

**http-message-signatures:**

```javascript
const { httpbis: { signMessage }, createSigner } = require("http-message-signatures");

const key = createSigner("sharedsecret", "hmac-sha256", "my-key-id");
const signedRequest = await signMessage(
  { key, fields: ["@method", "@authority", "content-type"] },
  {
    method: "POST",
    url: "https://example.com/foo",
    headers: { "Content-Type": "application/json" },
  }
);
// signedRequest.headers now contains Signature and Signature-Input
```

Differences to notice: http-fields-signatures returns the two header values
(you attach them), takes the key as raw material, and omits the `alg`
parameter from `Signature-Input` unless you pass `includeAlg: true` (RFC 9421
§7.3.6 favors deriving the algorithm from key metadata). http-message-signatures
returns a new message object and includes `alg`/`expires` by default.

### Verifying a request

**http-fields-signatures:**

```javascript
import { verifyMessage } from "http-fields-signatures";

const results = await verifyMessage(request, {
  getKey: ({ keyid }) => ({ alg: "hmac-sha256", key: keys.get(keyid) }),
});
// [{ label: "sig1", verified: true, params, components }]
// bad signature => { verified: false, reason: "Signature mismatch" }
```

**http-message-signatures:**

```javascript
const { httpbis: { verifyMessage }, createVerifier } = require("http-message-signatures");

const keys = new Map([
  ["my-key-id", {
    id: "my-key-id",
    algs: ["hmac-sha256"],
    verify: createVerifier("sharedsecret", "hmac-sha256"),
  }],
]);
const verified = await verifyMessage(
  { keyLookup: (params) => keys.get(params.keyid) },
  request
);
```

Differences: the key-resolution hook is `getKey` returning key material vs
`keyLookup` returning a verifier object; and failure handling — this library
reports each signature label separately with a `reason` (one bad signature
doesn't mask others), while `verifyMessage` there resolves/throws for the
message.

### Response bound to its request

**http-fields-signatures** — the request rides along on the response message,
and `;req`-flagged components pull from it:

```javascript
await signMessage(
  { status: 200, headers, request },
  {
    alg: "ecdsa-p256-sha256",
    key: privateJwk,
    keyid: "my-key-id",
    components: ["@status", { id: "@method", params: { req: true } }],
  }
);
```

**http-message-signatures** — the request is a separate trailing argument:

```javascript
await verifyMessage({ keyLookup }, response, request);
```

## Which to pick

Choose **http-message-signatures** when you need the **legacy Cavage draft**
(older peers still speak it), or when your keys live in a **KMS or secure
enclave** and you need to plug in a custom `sign()` callback rather than
importable key material.

Choose **http-fields-signatures** when you want the **final RFC 9421**
semantics validated **byte-exactly against the RFC's own Appendix B vectors**,
a **WebCrypto-only** implementation that runs unchanged in browsers and edge
runtimes, flexible key input (JWK/PEM/SEC1/CryptoKey/raw), or per-label
verification results instead of throw-based control flow.

Both are reasonable choices — this comparison reflects
`http-message-signatures@1.0.6` and may drift as either library evolves.
