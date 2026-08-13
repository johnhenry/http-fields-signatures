/**
 * RFC 9421 signature algorithms (§3.3) over WebCrypto.
 *
 * Keys are accepted as: a CryptoKey, a JWK object, a PEM string (PKCS#8
 * private or SPKI public), or raw bytes (Uint8Array, HMAC only).
 */

"use strict";

const subtle = globalThis.crypto?.subtle;
if (!subtle) {
  throw new Error("WebCrypto (globalThis.crypto.subtle) is required");
}

export const ALGORITHMS = {
  "rsa-pss-sha512": {
    importParams: { name: "RSA-PSS", hash: "SHA-512" },
    signParams: { name: "RSA-PSS", saltLength: 64 },
  },
  "rsa-v1_5-sha256": {
    importParams: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    signParams: { name: "RSASSA-PKCS1-v1_5" },
  },
  "ecdsa-p256-sha256": {
    importParams: { name: "ECDSA", namedCurve: "P-256" },
    signParams: { name: "ECDSA", hash: "SHA-256" },
  },
  "ecdsa-p384-sha384": {
    importParams: { name: "ECDSA", namedCurve: "P-384" },
    signParams: { name: "ECDSA", hash: "SHA-384" },
  },
  ed25519: {
    importParams: { name: "Ed25519" },
    signParams: { name: "Ed25519" },
  },
  "hmac-sha256": {
    importParams: { name: "HMAC", hash: "SHA-256" },
    signParams: { name: "HMAC" },
  },
};

const bytesFromB64 = (b64) => {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
};

const pemToBytes = (pem, label) => {
  const match = pem.match(
    new RegExp(`-----BEGIN ${label}-----([A-Za-z0-9+/=\\s]+)-----END ${label}-----`)
  );
  if (!match) return null;
  return bytesFromB64(match[1].replace(/\s+/g, ""));
};

// --- SEC1 → PKCS#8 transcoding ---------------------------------------------
// WebCrypto cannot import SEC1 "EC PRIVATE KEY" DER (RFC 5915) directly, but
// PKCS#8 is just an ASN.1 envelope around it:
//   SEQUENCE { INTEGER 0, SEQUENCE { id-ecPublicKey, curveOID }, OCTET STRING <SEC1> }
// No cryptography involved — pure DER re-packaging.

const OID_EC_PUBLIC_KEY = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const CURVE_OIDS = {
  "P-256": [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
  "P-384": [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
  "P-521": [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
};

const derTlv = (tag, contents) => {
  const len = contents.length;
  let header;
  if (len < 0x80) header = [tag, len];
  else if (len < 0x100) header = [tag, 0x81, len];
  else header = [tag, 0x82, len >> 8, len & 0xff];
  return Uint8Array.from([...header, ...contents]);
};

// Minimal DER walk over the SEC1 ECPrivateKey to find the [0] curve
// parameters (an OID), when present.
const sec1CurveOid = (sec1) => {
  if (sec1[0] !== 0x30) throw new Error("SEC1 key must start with a SEQUENCE");
  let offset = 2;
  if (sec1[1] & 0x80) offset = 2 + (sec1[1] & 0x7f);
  while (offset < sec1.length) {
    const tag = sec1[offset];
    let len = sec1[offset + 1];
    let headerLen = 2;
    if (len & 0x80) {
      const lenBytes = len & 0x7f;
      len = 0;
      for (let i = 0; i < lenBytes; i++) len = (len << 8) | sec1[offset + 2 + i];
      headerLen = 2 + lenBytes;
    }
    if (tag === 0xa0) {
      // [0] explicit: contents are the curve OID TLV
      return [...sec1.slice(offset + headerLen, offset + headerLen + len)];
    }
    offset += headerLen + len;
  }
  return null;
};

/**
 * Wrap SEC1 "EC PRIVATE KEY" DER bytes in a PKCS#8 envelope so WebCrypto can
 * import them. The curve is read from the key's [0] parameters when present,
 * else taken from `namedCurve` ("P-256" | "P-384" | "P-521").
 * @param {Uint8Array} sec1 - DER bytes of the ECPrivateKey
 * @param {string} [namedCurve] - fallback curve name
 * @returns {Uint8Array} PKCS#8 DER bytes
 */
export const sec1ToPkcs8 = (sec1, namedCurve) => {
  const curveOid = sec1CurveOid(sec1) ?? CURVE_OIDS[namedCurve];
  if (!curveOid) {
    throw new Error(
      "SEC1 key has no curve parameters; a namedCurve is required"
    );
  }
  const algorithmId = derTlv(0x30, [...OID_EC_PUBLIC_KEY, ...curveOid]);
  const version = Uint8Array.from([0x02, 0x01, 0x00]);
  const privateKey = derTlv(0x04, sec1);
  return derTlv(0x30, [...version, ...algorithmId, ...privateKey]);
};

/**
 * Import key material for an algorithm.
 * @param {string} alg - RFC 9421 algorithm name (e.g. "ed25519")
 * @param {CryptoKey|object|string|Uint8Array} material - CryptoKey, JWK,
 *   PEM (PKCS#8/SPKI), or raw bytes (HMAC)
 * @param {"sign"|"verify"} usage
 * @returns {Promise<CryptoKey>}
 */
export const importKey = async (alg, material, usage) => {
  const spec = ALGORITHMS[alg];
  if (!spec) throw new Error(`Unsupported algorithm: ${alg}`);

  if (material && typeof material === "object" && material.type && material.algorithm) {
    return material; // already a CryptoKey
  }

  if (material instanceof Uint8Array) {
    if (alg !== "hmac-sha256") {
      throw new Error("Raw byte keys are only supported for hmac-sha256");
    }
    return subtle.importKey("raw", material, spec.importParams, false, [
      "sign",
      "verify",
    ]);
  }

  if (typeof material === "object") {
    // JWK: private keys carry "d"
    const usages =
      alg === "hmac-sha256" ? ["sign", "verify"] : [material.d ? "sign" : "verify"];
    return subtle.importKey("jwk", material, spec.importParams, false, usages);
  }

  if (typeof material === "string") {
    // Encrypted keys are out of scope: decrypting them means PBES2/PBKDF2 key
    // derivation, not DER re-packaging. Decrypt once with
    // `openssl pkcs8 -topk8 -nocrypt` and pass the result instead.
    if (
      material.includes("ENCRYPTED PRIVATE KEY") ||
      /Proc-Type:\s*4\s*,\s*ENCRYPTED/.test(material)
    ) {
      throw new Error(
        "Encrypted private keys are not supported; decrypt first, e.g. " +
          "`openssl pkcs8 -topk8 -nocrypt -in key.pem`"
      );
    }
    const pkcs8 = pemToBytes(material, "PRIVATE KEY");
    if (pkcs8) {
      return subtle.importKey("pkcs8", pkcs8, spec.importParams, false, ["sign"]);
    }
    const sec1 = pemToBytes(material, "EC PRIVATE KEY");
    if (sec1) {
      const wrapped = sec1ToPkcs8(sec1, spec.importParams.namedCurve);
      return subtle.importKey("pkcs8", wrapped, spec.importParams, false, ["sign"]);
    }
    const spki = pemToBytes(material, "PUBLIC KEY");
    if (spki) {
      return subtle.importKey("spki", spki, spec.importParams, false, ["verify"]);
    }
    throw new Error(
      "PEM must contain a PKCS#8/SEC1 private key or SPKI PUBLIC KEY block"
    );
  }

  throw new Error(`Unsupported key material for ${usage}`);
};

/**
 * Sign a signature base with the given algorithm and key.
 * @returns {Promise<Uint8Array>} raw signature bytes
 */
export const signBase = async (alg, key, base) => {
  const spec = ALGORITHMS[alg];
  if (!spec) throw new Error(`Unsupported algorithm: ${alg}`);
  const cryptoKey = await importKey(alg, key, "sign");
  const data = new TextEncoder().encode(base);
  const sig = await subtle.sign(spec.signParams, cryptoKey, data);
  return new Uint8Array(sig);
};

/**
 * Verify raw signature bytes over a signature base.
 * @returns {Promise<boolean>}
 */
export const verifyBase = async (alg, key, signature, base) => {
  const spec = ALGORITHMS[alg];
  if (!spec) throw new Error(`Unsupported algorithm: ${alg}`);
  const cryptoKey = await importKey(alg, key, "verify");
  const data = new TextEncoder().encode(base);
  return subtle.verify(spec.signParams, cryptoKey, signature, data);
};
