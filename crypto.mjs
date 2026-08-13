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
    const pkcs8 = pemToBytes(material, "PRIVATE KEY");
    if (pkcs8) {
      return subtle.importKey("pkcs8", pkcs8, spec.importParams, false, ["sign"]);
    }
    const spki = pemToBytes(material, "PUBLIC KEY");
    if (spki) {
      return subtle.importKey("spki", spki, spec.importParams, false, ["verify"]);
    }
    throw new Error(
      "PEM must contain a PKCS#8 PRIVATE KEY or SPKI PUBLIC KEY block"
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
