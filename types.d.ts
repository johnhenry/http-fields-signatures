// Type definitions for http-fields-signatures
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
  /** Unix seconds used for expires checking; defaults to now. */
  now?: number;
  fieldTypes?: FieldTypes;
}

export declare function verifyMessage(
  message: Message,
  options: VerifyOptions
): Promise<VerifyResult[]>;
