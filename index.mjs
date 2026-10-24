/**
 * @johnhenry/http-fields-signatures — RFC 9421 HTTP Message Signatures.
 *
 * Built on `@johnhenry/http-fields` (RFC 8941/9651 Structured Field Values) for all
 * header parsing/serialization, and WebCrypto for the cryptography.
 */

"use strict";

import { parse, serialize, binary } from "@johnhenry/http-fields";
import {
  createSignatureBase,
  getHeaderValues,
  normalizeComponent,
  serializeComponentIdentifier,
} from "./base.mjs";
import { ALGORITHMS, importKey, signBase, verifyBase } from "./crypto.mjs";

export { createSignatureBase, getHeaderValues } from "./base.mjs";
export {
  ALGORITHMS,
  importKey,
  signBase,
  verifyBase,
  sec1ToPkcs8,
} from "./crypto.mjs";
export {
  DIGEST_ALGORITHMS,
  createContentDigest,
  verifyContentDigest,
} from "./digest.mjs";

const bytesToB64 = (bytes) => {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin);
};

const b64ToBytes = (b64) => {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
};

/**
 * Parse `Signature-Input` and `Signature` header values into per-label
 * entries: {label: {components: [{id, params}], params, signature?}}.
 * Either argument may be undefined.
 */
export const parseSignatureHeaders = (signatureInput, signature) => {
  const entries = {};
  if (signatureInput !== undefined) {
    const dict = parse(signatureInput, "dictionary");
    for (const [label, member] of Object.entries(dict)) {
      if (!Array.isArray(member.value)) {
        throw new Error(`Signature-Input member "${label}" must be an inner list`);
      }
      const components = member.value.map((item) => {
        if (typeof item.value !== "string") {
          throw new Error("Covered components must be strings");
        }
        return { id: item.value, params: item.parameters };
      });
      entries[label] = { components, params: member.parameters };
    }
  }
  if (signature !== undefined) {
    const dict = parse(signature, "dictionary");
    for (const [label, member] of Object.entries(dict)) {
      const v = member.value;
      if (!v || v.type !== "binary") {
        throw new Error(`Signature member "${label}" must be a byte sequence`);
      }
      entries[label] = entries[label] || {};
      entries[label].signature = b64ToBytes(v.value);
    }
  }
  return entries;
};

/**
 * Sign an HTTP message (RFC 9421).
 *
 * @param {object} message - {method, url, headers} or {status, headers, request?}
 * @param {object} options
 * @param {string} options.alg - algorithm name (see ALGORITHMS)
 * @param {CryptoKey|object|string|Uint8Array} options.key - signing key
 * @param {Array<string|{id, params}>} [options.components=[]] - covered components
 * @param {string} [options.label="sig1"] - signature label
 * @param {string} [options.keyid]
 * @param {number} [options.created=now] - unix seconds; pass null to omit
 * @param {number} [options.expires]
 * @param {string} [options.nonce]
 * @param {string} [options.tag]
 * @param {boolean} [options.includeAlg=false] - include the alg parameter
 * @param {object} [options.fieldTypes] - field name → SFV type, for ;sf
 * @returns {Promise<{signatureInput: string, signature: string, base: string,
 *   label: string}>} header values to add to the message
 */
export const signMessage = async (message, options) => {
  const {
    alg,
    key,
    components = [],
    label = "sig1",
    keyid,
    created = Math.floor(Date.now() / 1000),
    expires,
    nonce,
    tag,
    includeAlg = false,
    fieldTypes,
  } = options;

  if (!ALGORITHMS[alg]) throw new Error(`Unsupported algorithm: ${alg}`);

  // Parameter order follows the RFC 9421 examples: created, expires, alg,
  // keyid, then nonce/tag
  const params = {};
  if (created !== null && created !== undefined) params.created = created;
  if (expires !== undefined) params.expires = expires;
  if (includeAlg) params.alg = alg;
  if (keyid !== undefined) params.keyid = keyid;
  if (nonce !== undefined) params.nonce = nonce;
  if (tag !== undefined) params.tag = tag;

  const { base } = createSignatureBase(message, components, params, { fieldTypes });
  const signatureBytes = await signBase(alg, key, base);

  const inner = components.map(normalizeComponent).map(({ id, params: p }) => ({
    value: id.toLowerCase(),
    parameters: p,
  }));
  const signatureInput = serialize(
    { [label]: { value: inner, parameters: params } },
    "dictionary"
  );
  const signature = serialize(
    { [label]: { value: binary(bytesToB64(signatureBytes)), parameters: {} } },
    "dictionary"
  );

  return { signatureInput, signature, base, label };
};

const componentKey = (component) =>
  serializeComponentIdentifier(normalizeComponent(component));

/**
 * Verify the signatures on an HTTP message (RFC 9421).
 *
 * Reads `Signature-Input`/`Signature` from message.headers unless provided
 * via options. Structural problems throw; cryptographic mismatch and policy
 * failures report as verified:false with a reason.
 *
 * Policy options are all opt-in; with none set, the only time-based check is
 * that `expires` (when present) is not in the past. Checks run in this order:
 * expires, created (clockSkew / maxAge), tag, requiredComponents, key
 * lookup, alg agreement, cryptographic verification, and finally the nonce
 * callback (only for otherwise-valid signatures, so invalid ones never
 * consume a nonce).
 *
 * @param {object} message
 * @param {object} options
 * @param {(context: {label: string, keyid?: string, alg?: string}) =>
 *   (object|Promise<object>)} options.getKey - resolves {alg, key} (or just a
 *   key when the signature's alg parameter should be trusted) for a
 *   signature. If both the resolved alg and the signature's alg parameter
 *   are present they must be equal (RFC 9421 §3.2), or verification fails.
 * @param {string} [options.label] - verify only this label
 * @param {string} [options.signatureInput] - override header lookup
 * @param {string} [options.signature] - override header lookup
 * @param {number} [options.now=now] - unix seconds for time checks
 * @param {number} [options.clockSkew] - tolerance in seconds applied to the
 *   expires/created checks. Setting it (or maxAge) also rejects signatures
 *   whose `created` is more than clockSkew seconds in the future.
 * @param {number} [options.maxAge] - require `created` and reject signatures
 *   older than this many seconds (plus clockSkew)
 * @param {string|string[]} [options.tag] - require the `tag` parameter to
 *   equal this value (or one of these values)
 * @param {Array<string|{id, params}>} [options.requiredComponents] -
 *   components every accepted signature must cover
 * @param {(nonce: string, context: {label: string, keyid?: string,
 *   params: object}) => (boolean|Promise<boolean>)} [options.checkNonce] -
 *   when set, a `nonce` parameter is required and the callback must return
 *   true (e.g. after recording it as seen) for the signature to verify
 * @param {object} [options.fieldTypes]
 * @returns {Promise<Array<{label: string, verified: boolean, reason?: string,
 *   params: object, components: Array<{id, params}>}>>}
 */
export const verifyMessage = async (message, options) => {
  const {
    getKey,
    label: onlyLabel,
    now = Math.floor(Date.now() / 1000),
    clockSkew,
    maxAge,
    tag,
    requiredComponents,
    checkNonce,
    fieldTypes,
  } = options;

  for (const [name, value] of [
    ["clockSkew", clockSkew],
    ["maxAge", maxAge],
  ]) {
    if (value !== undefined && !(Number.isFinite(value) && value >= 0)) {
      throw new TypeError(`${name} must be a non-negative number`);
    }
  }
  if (checkNonce !== undefined && typeof checkNonce !== "function") {
    throw new TypeError("checkNonce must be a function");
  }
  const skew = clockSkew ?? 0;
  const checkCreated = clockSkew !== undefined || maxAge !== undefined;
  const allowedTags =
    tag === undefined ? undefined : Array.isArray(tag) ? tag : [tag];
  const required = (requiredComponents ?? []).map(componentKey);

  const signatureInput =
    options.signatureInput ??
    getHeaderValues(message.headers, "signature-input").join(", ");
  const signature =
    options.signature ?? getHeaderValues(message.headers, "signature").join(", ");
  if (!signatureInput) throw new Error("No Signature-Input to verify");

  const entries = parseSignatureHeaders(signatureInput, signature || undefined);
  const results = [];

  for (const [label, entry] of Object.entries(entries)) {
    if (onlyLabel && label !== onlyLabel) continue;
    if (!entry.components) {
      results.push({
        label,
        verified: false,
        reason: "No Signature-Input for this label",
        params: {},
        components: [],
      });
      continue;
    }
    const { components, params } = entry;
    const result = { label, verified: false, params, components };
    results.push(result);

    if (!entry.signature) {
      result.reason = "No Signature value for this label";
      continue;
    }
    if (Number.isInteger(params.expires) && params.expires + skew < now) {
      result.reason = "Signature expired";
      continue;
    }
    if (checkCreated) {
      const hasCreated = Number.isInteger(params.created);
      if (maxAge !== undefined && !hasCreated) {
        result.reason = "Missing created parameter";
        continue;
      }
      if (hasCreated && params.created > now + skew) {
        result.reason = "Signature created in the future";
        continue;
      }
      if (maxAge !== undefined && now - params.created > maxAge + skew) {
        result.reason = "Signature too old";
        continue;
      }
    }
    if (allowedTags && !allowedTags.includes(params.tag)) {
      result.reason = "Tag mismatch";
      continue;
    }
    if (required.length) {
      const covered = new Set(components.map(componentKey));
      const missing = required.filter((id) => !covered.has(id));
      if (missing.length) {
        result.reason = `Missing required components: ${missing.join(" ")}`;
        continue;
      }
    }

    const keyid = typeof params.keyid === "string" ? params.keyid : undefined;
    const sigAlg = typeof params.alg === "string" ? params.alg : undefined;
    const resolved = await getKey({ label, keyid, alg: sigAlg });
    if (!resolved) {
      result.reason = "Key not found";
      continue;
    }
    // {alg?, key} wrapper vs. bare key material. A bare JWK may carry its
    // own (JOSE) "alg" member, which is not an RFC 9421 algorithm name.
    const wrapped =
      typeof resolved === "object" &&
      !(resolved instanceof Uint8Array) &&
      resolved.key !== undefined;
    const keyAlg = wrapped ? resolved.alg : undefined;
    const key = wrapped ? resolved.key : resolved;
    if (keyAlg !== undefined && sigAlg !== undefined && keyAlg !== sigAlg) {
      result.reason = `Algorithm mismatch: key is ${keyAlg}, signature declares ${sigAlg}`;
      continue;
    }
    const alg = keyAlg ?? sigAlg;
    if (!ALGORITHMS[alg]) {
      result.reason = `Unsupported algorithm: ${alg}`;
      continue;
    }

    const { base } = createSignatureBase(message, components, params, {
      fieldTypes,
    });
    const ok = await verifyBase(alg, key, entry.signature, base);
    if (!ok) {
      result.reason = "Signature mismatch";
      continue;
    }

    if (checkNonce) {
      if (typeof params.nonce !== "string") {
        result.reason = "Missing nonce";
        continue;
      }
      const accepted = await checkNonce(params.nonce, { label, keyid, params });
      if (accepted !== true) {
        result.reason = "Nonce rejected";
        continue;
      }
    }
    result.verified = true;
  }

  if (onlyLabel && results.length === 0) {
    throw new Error(`No signature labeled "${onlyLabel}" found`);
  }
  return results;
};

/**
 * Adapt a Fetch API `Request` into a message for signMessage/verifyMessage.
 * Only method, URL and headers are read; the body is untouched (use
 * createContentDigest / verifyContentDigest for it).
 *
 * @param {Request} request
 * @returns {{method: string, url: string, headers: Headers}}
 */
export const fromFetchRequest = (request) => ({
  method: request.method,
  url: request.url,
  headers: request.headers,
});

/**
 * Adapt a Fetch API `Response` into a message. Pass the related `Request`
 * (or an already-adapted request message) to enable `;req` components.
 *
 * @param {Response} response
 * @param {Request|object} [request]
 * @returns {{status: number, headers: Headers, request?: object}}
 */
export const fromFetchResponse = (response, request) => {
  const message = { status: response.status, headers: response.headers };
  if (request !== undefined) {
    message.request =
      typeof Request !== "undefined" && request instanceof Request
        ? fromFetchRequest(request)
        : request;
  }
  return message;
};
