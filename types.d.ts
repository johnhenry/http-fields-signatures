// Type definitions for @johnhenry/http-fields-signatures
// Project: https://github.com/johnhenry/http-fields-signatures

/** HTTP request message (runtime-agnostic). */
export interface RequestMessage {
  method: string;
  /** Absolute URL. */
  url: string;
  headers: HeadersLike;
}

/** HTTP response message. `request` enables `;req`-flagged components. */
export interface ResponseMessage {
  status: number;
  headers: HeadersLike;
  request?: RequestMessage;
}

export type Message = RequestMessage | ResponseMessage;

/** Plain object, entries array, or Fetch-style Headers. */
export type HeadersLike =
  | Record<string, string | string[]>
  | Array<[string, string]>
  | { entries(): IterableIterator<[string, string]>; get(name: string): string | null };

/** Covered component: a bare id or an id with identifier parameters. */
export type ComponentSpec =
  | string
  | {
      id: string;
      params?: {
        /** @query-param: the (re-encoded) parameter name. */
        name?: string;
        /** Field: select a dictionary member. */
        key?: string;
        /** Field: strict structured-field re-serialization. */
        sf?: boolean;
        /** Field: wrap raw value(s) as byte sequences. */
        bs?: boolean;
        /** Response signing: take the component from the related request. */
        req?: boolean;
      };
    };

export interface Component {
  id: string;
  params: Record<string, unknown>;
}

/** created/expires/nonce/alg/keyid/tag, serialized in insertion order. */
export type SignatureParams = Record<string, unknown>;

export type FieldTypes = Record<string, "list" | "dictionary" | "item">;

/** JWK object, PEM string (PKCS#8/SPKI), raw bytes (HMAC), or a CryptoKey. */
export type KeyMaterial = CryptoKey | object | string | Uint8Array;

export type AlgorithmName =
  | "rsa-pss-sha512"
  | "rsa-v1_5-sha256"
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "ed25519"
  | "hmac-sha256";

export declare const ALGORITHMS: Record<
  AlgorithmName,
  { importParams: object; signParams: object }
>;

export declare function createSignatureBase(
  message: Message,
  components: ComponentSpec[],
  signatureParams: SignatureParams,
  options?: { fieldTypes?: FieldTypes }
): { base: string; signatureParamsValue: string };

export declare function getHeaderValues(
  headers: HeadersLike,
  name: string
): string[];

/**
 * Wrap SEC1 "EC PRIVATE KEY" DER bytes in a PKCS#8 envelope so WebCrypto can
 * import them. Pure ASN.1 re-packaging; no cryptography involved.
 */
export declare function sec1ToPkcs8(
  sec1: Uint8Array,
  namedCurve?: "P-256" | "P-384" | "P-521"
): Uint8Array;

export declare function importKey(
  alg: AlgorithmName,
  material: KeyMaterial,
  usage: "sign" | "verify"
): Promise<CryptoKey>;

export declare function signBase(
  alg: AlgorithmName,
  key: KeyMaterial,
  base: string
): Promise<Uint8Array>;

export declare function verifyBase(
  alg: AlgorithmName,
  key: KeyMaterial,
  signature: Uint8Array,
  base: string
): Promise<boolean>;

export declare function parseSignatureHeaders(
  signatureInput?: string,
  signature?: string
): Record<
  string,
  { components?: Component[]; params?: SignatureParams; signature?: Uint8Array }
>;

export interface SignOptions {
  alg: AlgorithmName;
  key: KeyMaterial;
  components?: ComponentSpec[];
  label?: string;
  keyid?: string;
  /** Unix seconds; defaults to now. Pass null to omit. */
  created?: number | null;
  expires?: number;
  nonce?: string;
  tag?: string;
  /** Include the alg parameter in Signature-Input (default false). */
  includeAlg?: boolean;
  fieldTypes?: FieldTypes;
}

export declare function signMessage(
  message: Message,
  options: SignOptions
): Promise<{
  signatureInput: string;
  signature: string;
  base: string;
  label: string;
}>;

export interface VerifyResult {
  label: string;
  verified: boolean;
  reason?: string;
  params: SignatureParams;
  components: Component[];
}

export interface VerifyOptions {
  /**
   * Resolve the verification key. Return `{alg, key}` or bare key material
   * (then the signature's `alg` parameter is used). If both `alg`s are
   * present and differ, verification fails (RFC 9421 §3.2).
   */
  getKey: (context: {
    label: string;
    keyid?: string;
    alg?: string;
  }) =>
    | KeyMaterial
    | { alg?: AlgorithmName; key: KeyMaterial }
    | Promise<KeyMaterial | { alg?: AlgorithmName; key: KeyMaterial }>;
  label?: string;
  signatureInput?: string;
  signature?: string;
  /** Unix seconds used for time checks; defaults to now. */
  now?: number;
  /**
   * Tolerance in seconds for the expires/created checks. Setting it (or
   * maxAge) also refuses signatures whose `created` is more than clockSkew
   * seconds in the future. Default: no tolerance, no created check.
   */
  clockSkew?: number;
  /** Require `created` and refuse signatures older than this many seconds. */
  maxAge?: number;
  /** Require the `tag` parameter to equal this value (or one of these). */
  tag?: string | string[];
  /** Components every accepted signature must cover. */
  requiredComponents?: ComponentSpec[];
  /**
   * When set, a `nonce` parameter is required and this must return `true`
   * (sync or async). Called only for otherwise-valid signatures.
   */
  checkNonce?: (
    nonce: string,
    context: { label: string; keyid?: string; params: SignatureParams }
  ) => boolean | Promise<boolean>;
  fieldTypes?: FieldTypes;
}

export declare function verifyMessage(
  message: Message,
  options: VerifyOptions
): Promise<VerifyResult[]>;


// --- Content-Digest (RFC 9530) ---------------------------------------------

export type DigestAlgorithmName = "sha-256" | "sha-512";

/** Body accepted by the digest helpers; strings are UTF-8 encoded. */
export type DigestBody = string | Uint8Array | ArrayBuffer | ArrayBufferView | Blob;

export declare const DIGEST_ALGORITHMS: Record<
  DigestAlgorithmName,
  { hash: string; strength: number }
>;

/** Create a Content-Digest header value, e.g. `sha-256=:<base64>:`. */
export declare function createContentDigest(
  body: DigestBody,
  options?: { algorithms?: DigestAlgorithmName | DigestAlgorithmName[] }
): Promise<string>;

/**
 * Verify a body against a Content-Digest header value. Unknown algorithms
 * are ignored; every supported digest present must match; `algorithm` is
 * the strongest one used.
 */
export declare function verifyContentDigest(
  body: DigestBody,
  header: string | string[] | undefined,
  options?: { algorithms?: DigestAlgorithmName[] }
): Promise<{ verified: boolean; algorithm?: DigestAlgorithmName; reason?: string }>;

// --- Fetch adapters ----------------------------------------------------------

/** Adapt a Fetch `Request` (method, url, headers; body untouched). */
export declare function fromFetchRequest(request: Request): RequestMessage;

/** Adapt a Fetch `Response`; pass the related request to enable `;req`. */
export declare function fromFetchResponse(
  response: Response,
  request?: Request | RequestMessage
): ResponseMessage;
