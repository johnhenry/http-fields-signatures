/**
 * RFC 9530 Digest Fields — `Content-Digest` creation and verification.
 *
 * Header values are Structured Field dictionaries whose keys are algorithm
 * names and whose values are byte sequences, e.g. `sha-256=:<base64>:`.
 * Parsing/serialization goes through `@johnhenry/http-fields`; hashing goes
 * through WebCrypto.
 */

"use strict";

import { parse, serialize, binary } from "@johnhenry/http-fields";

const subtle = globalThis.crypto?.subtle;
if (!subtle) {
  throw new Error("WebCrypto (globalThis.crypto.subtle) is required");
}

/**
 * Supported digest algorithms (RFC 9530 §5 "Active" registrations), ordered
 * strongest first. Insecure/deprecated ones (md5, sha, unixsum, ...) are
 * deliberately absent and are ignored when encountered.
 */
export const DIGEST_ALGORITHMS = {
  "sha-512": { hash: "SHA-512", strength: 512 },
  "sha-256": { hash: "SHA-256", strength: 256 },
};

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

/** Normalize a body (string, bytes, ArrayBuffer, view, or Blob) to bytes. */
const toBytes = async (body) => {
  if (body === undefined || body === null) return new Uint8Array(0);
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (ArrayBuffer.isView(body)) {
    return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  }
  if (typeof body.arrayBuffer === "function") {
    return new Uint8Array(await body.arrayBuffer());
  }
  throw new TypeError(
    "Body must be a string, Uint8Array, ArrayBuffer, ArrayBufferView, or Blob"
  );
};

const digest = async (algorithm, bytes) =>
  new Uint8Array(await subtle.digest(DIGEST_ALGORITHMS[algorithm].hash, bytes));

const equalBytes = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

/**
 * Create a `Content-Digest` header value for a body.
 *
 * @param {string|Uint8Array|ArrayBuffer|ArrayBufferView|Blob} body - the
 *   message content (strings are UTF-8 encoded)
 * @param {object} [options]
 * @param {string|string[]} [options.algorithms="sha-256"] - one or more of
 *   "sha-256", "sha-512"
 * @returns {Promise<string>} e.g. `sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:`
 */
export const createContentDigest = async (body, options = {}) => {
  const { algorithms = "sha-256" } = options;
  const list = Array.isArray(algorithms) ? algorithms : [algorithms];
  if (list.length === 0) throw new Error("At least one digest algorithm is required");
  const bytes = await toBytes(body);
  const dict = {};
  for (const algorithm of list) {
    if (!DIGEST_ALGORITHMS[algorithm]) {
      throw new Error(`Unsupported digest algorithm: ${algorithm}`);
    }
    dict[algorithm] = {
      value: binary(bytesToB64(await digest(algorithm, bytes))),
      parameters: {},
    };
  }
  return serialize(dict, "dictionary");
};

/**
 * Verify a received body against a `Content-Digest` header value.
 *
 * Unknown or unsupported algorithms in the header are ignored. Every
 * supported (and allowed) digest present must match the body; the result
 * reports the strongest one used. If no supported digest is present the
 * body is not verified.
 *
 * Structural problems (an unparseable header) throw; a missing header, no
 * usable algorithm, or a mismatch report as `{verified: false, reason}`.
 *
 * @param {string|Uint8Array|ArrayBuffer|ArrayBufferView|Blob} body
 * @param {string|string[]|undefined} header - Content-Digest value(s)
 * @param {object} [options]
 * @param {string[]} [options.algorithms] - restrict which algorithms are
 *   accepted (default: all of DIGEST_ALGORITHMS)
 * @returns {Promise<{verified: boolean, algorithm?: string, reason?: string}>}
 */
export const verifyContentDigest = async (body, header, options = {}) => {
  const { algorithms = Object.keys(DIGEST_ALGORITHMS) } = options;
  const value = Array.isArray(header) ? header.join(", ") : header;
  if (value === undefined || value === null || value.trim() === "") {
    return { verified: false, reason: "No Content-Digest" };
  }
  const dict = parse(value, "dictionary");

  const candidates = Object.keys(dict)
    .filter((name) => DIGEST_ALGORITHMS[name] && algorithms.includes(name))
    .sort((a, b) => DIGEST_ALGORITHMS[b].strength - DIGEST_ALGORITHMS[a].strength);
  if (candidates.length === 0) {
    return { verified: false, reason: "No supported digest algorithm" };
  }

  const bytes = await toBytes(body);
  for (const algorithm of candidates) {
    const member = dict[algorithm].value;
    if (!member || member.type !== "binary") {
      return {
        verified: false,
        algorithm,
        reason: `Digest for ${algorithm} must be a byte sequence`,
      };
    }
    const expected = b64ToBytes(member.value);
    if (!equalBytes(expected, await digest(algorithm, bytes))) {
      return { verified: false, algorithm, reason: "Digest mismatch" };
    }
  }
  return { verified: true, algorithm: candidates[0] };
};
