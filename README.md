# @johnhenry/http-fields-signatures

> Previously published as the unscoped `http-fields-signatures` (0.1.0). This scoped package continues that line at 0.2.0 and depends on `@johnhenry/http-fields`.

[RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) **HTTP Message
Signatures** for JavaScript — sign and verify HTTP requests and responses.

Built on [`http-fields`](https://github.com/johnhenry/http-fields) (RFC
8941/9651 Structured Field Values) for all header parsing/serialization, and
on WebCrypto for the cryptography. Runtime-agnostic: Node.js ≥ 26 (the
`engines` range, and the version CI tests), browsers, and edge runtimes with
`globalThis.crypto.subtle` (including Ed25519 support).

Validated against the complete RFC 9421 Appendix B test suite: all six
signature bases are reproduced byte-exactly, the RFC's RSA-PSS and ECDSA
example signatures verify, and HMAC/Ed25519 signing reproduces the RFC's
exact signature bytes.

## Installation

```bash
npm install @johnhenry/http-fields-signatures
```

## Quick Start

### Signing a request

```javascript
import { signMessage } from "@johnhenry/http-fields-signatures";

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
import { verifyMessage } from "@johnhenry/http-fields-signatures";

const results = await verifyMessage(request, {
  getKey: ({ keyid }) => ({ alg: "ed25519", key: publicKeys[keyid] }),
});
// [{ label: "sig1", verified: true, params: {...}, components: [...] }]
```

Structural problems (unparseable headers) throw; cryptographic mismatches and
policy failures (expired signatures, unknown keys) report as
`{verified: false, reason}` so one bad signature doesn't mask others.

#### Verification policy

By default `verifyMessage` only checks the cryptography and that `expires`
(if present) is not in the past. **A signature that covers no components
verifies** unless you say otherwise, so set a policy:

```javascript
const results = await verifyMessage(request, {
  getKey,
  requiredComponents: ["@method", "@target-uri", "content-digest"],
  tag: "my-app",       // string or array of accepted tags
  maxAge: 300,         // require `created`, refuse if older than 5 minutes
  clockSkew: 30,       // tolerance for created/expires; also refuses future `created`
  checkNonce: async (nonce, { keyid }) => nonceStore.addIfNew(keyid, nonce),
});
```

| Option | Effect when set | Reason on failure |
| --- | --- | --- |
| `requiredComponents` | every listed component (with its parameters) must be covered | `Missing required components: ...` |
| `tag` | the `tag` parameter must equal the value (or one of the array) | `Tag mismatch` |
| `maxAge` | `created` is required and `now - created <= maxAge + clockSkew` | `Missing created parameter`, `Signature too old` |
| `clockSkew` | `expires + clockSkew >= now`; `created <= now + clockSkew` (the future-`created` check also runs when only `maxAge` is set) | `Signature expired`, `Signature created in the future` |
| `checkNonce` | a `nonce` is required and the (sync or async) callback must return `true`; it runs only after the signature verified, so invalid signatures never consume a nonce | `Missing nonce`, `Nonce rejected` |

All are opt-in, so existing callers see no change. `now` (unix seconds)
overrides the clock for every time check.

**Algorithm agreement (RFC 9421 §3.2):** `getKey` may return `{alg, key}`
or bare key material. With bare material the signature's `alg` parameter is
used. If both `getKey`'s `alg` and the signature's `alg` parameter are
present and differ, the signature is refused (`Algorithm mismatch: ...`)
rather than silently verified with the key's algorithm.

### Content-Digest (RFC 9530)

Sign `content-digest` to protect the body, and check the body against it:

```javascript
import {
  createContentDigest, verifyContentDigest,
} from "@johnhenry/http-fields-signatures";

request.headers["Content-Digest"] = await createContentDigest(body);
// sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
await createContentDigest(body, { algorithms: ["sha-256", "sha-512"] });

// receiver: verify the signature (covering content-digest), then the body
const digest = await verifyContentDigest(body, headers["content-digest"]);
// { verified: true, algorithm: "sha-512" }
```

Bodies may be strings (UTF-8), `Uint8Array`, `ArrayBuffer`, typed-array
views, or `Blob`s. Supported algorithms are `sha-256` and `sha-512`;
unknown or deprecated ones in a received header are ignored. Every supported
digest present must match, and `algorithm` reports the strongest one used.
No supported digest, a missing header, or a mismatch return
`{verified: false, reason}`; an unparseable header throws. Restrict accepted
algorithms with `{ algorithms: ["sha-512"] }`.

### Fetch `Request` / `Response`

```javascript
import { fromFetchRequest, fromFetchResponse } from "@johnhenry/http-fields-signatures";

const results = await verifyMessage(fromFetchRequest(request), { getKey });
const message = fromFetchResponse(response, request); // enables ;req components
```

The adapters read only method/URL/status/headers; read the body yourself
(e.g. `await request.clone().arrayBuffer()`) for `verifyContentDigest`.

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
  DIGEST_ALGORITHMS,
} from "@johnhenry/http-fields-signatures";

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
round-trip, tampering, and expiry tests, RFC 9530 Content-Digest vectors,
verification-policy, `alg`-agreement, and Fetch adapter tests.

## Alternatives

See [COMPARISON.md](COMPARISON.md) for a side-by-side comparison with
[`http-message-signatures`](https://github.com/dhensby/node-http-message-signatures),
including how to do the same signing/verifying tasks in each.

## License

MIT
