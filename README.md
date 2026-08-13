# http-fields-signatures

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) **HTTP Message
Signatures** for JavaScript — sign and verify HTTP requests and responses.

Built on [`http-fields`](https://github.com/johnhenry/http-fields) (RFC
8941/9651 Structured Field Values) for all header parsing/serialization, and
on WebCrypto for the cryptography. Runtime-agnostic: Node.js ≥ 20, browsers,
and edge runtimes with `globalThis.crypto.subtle`.

Validated against the complete RFC 9421 Appendix B test suite: all six
signature bases are reproduced byte-exactly, the RFC's RSA-PSS and ECDSA
example signatures verify, and HMAC/Ed25519 signing reproduces the RFC's
exact signature bytes.

## Installation

```bash
npm install http-fields-signatures
```

## Quick Start

### Signing a request

```javascript
import { signMessage } from "http-fields-signatures";

const request = {
  method: "POST",
  url: "https://example.com/foo?param=Value&Pet=dog",
  headers: {
    Date: "Tue, 20 Apr 2021 02:07:55 GMT",
    "Content-Type": "application/json",
  },
};

const { signatureInput, signature } = await signMessage(request, {
  alg: "ed25519",
  key: privateJwk, // JWK, PEM (PKCS#8), or CryptoKey
  keyid: "my-key",
  components: ["@method", "@path", "@authority", "content-type"],
});

request.headers["Signature-Input"] = signatureInput;
request.headers["Signature"] = signature;
// Signature-Input: sig1=("@method" "@path" "@authority" "content-type");created=...;keyid="my-key"
// Signature: sig1=:...base64...:
```

### Verifying

```javascript
import { verifyMessage } from "http-fields-signatures";

const results = await verifyMessage(request, {
  getKey: ({ keyid }) => ({ alg: "ed25519", key: publicKeys[keyid] }),
});
// [{ label: "sig1", verified: true, params: {...}, components: [...] }]
```

Structural problems (unparseable headers) throw; cryptographic mismatches and
policy failures (expired signatures, unknown keys) report as
`{verified: false, reason}` so one bad signature doesn't mask others.

### Signing a response (with request binding)

```javascript
const response = { status: 200, headers: {...}, request };

await signMessage(response, {
  alg: "ecdsa-p256-sha256",
  key: privateJwk,
  keyid: "my-key",
  components: [
    "@status",
    "content-type",
    { id: "@method", params: { req: true } }, // bind to the request's method
  ],
});
```

## Supported algorithms (RFC 9421 §3.3)

| Name | WebCrypto |
| --- | --- |
| `rsa-pss-sha512` | RSA-PSS, SHA-512, salt 64 |
| `rsa-v1_5-sha256` | RSASSA-PKCS1-v1_5, SHA-256 |
| `ecdsa-p256-sha256` | ECDSA P-256, SHA-256 |
| `ecdsa-p384-sha384` | ECDSA P-384, SHA-384 |
| `ed25519` | Ed25519 |
| `hmac-sha256` | HMAC, SHA-256 |

Keys are accepted as **CryptoKey**, **JWK** objects, **PEM** strings (PKCS#8
or SEC1 private / SPKI public), or raw **Uint8Array** bytes (HMAC).

WebCrypto itself cannot import SEC1 `EC PRIVATE KEY` PEMs (the format RFC
9421 uses for its P-256 example key), so `importKey` transparently re-wraps
them: PKCS#8 is just an ASN.1 envelope around the SEC1 payload, so the
conversion is pure DER re-packaging with no cryptography involved. The
transcoder is also exported directly as `sec1ToPkcs8(sec1Bytes, namedCurve?)`.

**Encrypted private keys are not supported.** Password-protected PEMs —
PKCS#8 `ENCRYPTED PRIVATE KEY` (PBES2) or legacy `Proc-Type: 4,ENCRYPTED`
blocks — require key-derivation cryptography, not byte re-packaging, and
`importKey` rejects them with a clear error. Decrypt once outside the
library instead:

```bash
openssl pkcs8 -topk8 -nocrypt -in encrypted-key.pem -out key.pem
```

## Covered components

Components are strings or `{id, params}` objects:

- **Derived** (from the message itself): `@method`, `@target-uri`,
  `@authority`, `@scheme`, `@request-target`, `@path`, `@query`,
  `@query-param` (`{id: "@query-param", params: {name: "Pet"}}`), `@status`
- **Fields**: any header name (lowercased), with optional parameters:
  - `key`: select one dictionary member (`{id: "example-dict", params: {key: "b"}}`)
  - `sf`: strict structured-field re-serialization (requires the field's type
    via `options.fieldTypes`)
  - `bs`: wrap raw value(s) as byte sequences
  - `req`: take the component from the related request when signing a response

## Lower-level API

```javascript
import {
  createSignatureBase, // build the §2.5 signature base string
  parseSignatureHeaders, // parse Signature-Input / Signature dictionaries
  signBase, verifyBase, // raw crypto over a base string
  importKey, ALGORITHMS,
} from "http-fields-signatures";

const { base } = createSignatureBase(request, ["@method", "content-type"], {
  created: 1618884473,
  keyid: "my-key",
});
```

## Messages

Messages are plain objects, so any client/server framework can adapt to them:

```javascript
// Request:  { method, url, headers }
// Response: { status, headers, request? }
```

`headers` may be a plain object (values `string` or `string[]`), an array of
`[name, value]` entries, or a Fetch-style `Headers` instance.

## Testing

```bash
npm test
```

The suite includes the full RFC 9421 Appendix B vectors (B.2.1–B.2.6) plus
round-trip, tampering, and expiry tests.

## Alternatives

See [COMPARISON.md](COMPARISON.md) for a side-by-side comparison with
[`http-message-signatures`](https://github.com/dhensby/node-http-message-signatures),
including how to do the same signing/verifying tasks in each.

## License

MIT
