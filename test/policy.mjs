import { test, describe } from "node:test";
import assert from "node:assert";
import {
  signMessage,
  verifyMessage,
  createContentDigest,
  verifyContentDigest,
  DIGEST_ALGORITHMS,
  fromFetchRequest,
  fromFetchResponse,
} from "../index.mjs";
import { KEYS, TEST_REQUEST } from "./vectors.mjs";

const ED = KEYS["test-key-ed25519"];
const BODY = '{"hello": "world"}';
// RFC 9530 / RFC 9421 Appendix B values for the body above
const SHA256 = "sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:";
const SHA512 =
  "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:";

const T = 1618884473;

const signed = async (signOptions = {}) => {
  const { signatureInput, signature } = await signMessage(TEST_REQUEST, {
    alg: "ed25519",
    key: ED.privateJwk,
    keyid: "test-key-ed25519",
    components: ["@method", "@authority", "content-digest"],
    created: T,
    ...signOptions,
  });
  return {
    ...TEST_REQUEST,
    headers: {
      ...TEST_REQUEST.headers,
      "Signature-Input": signatureInput,
      Signature: signature,
    },
  };
};

const getKey = () => ({ alg: "ed25519", key: ED.publicJwk });

const verifyOne = async (message, options = {}) => {
  const [result] = await verifyMessage(message, { getKey, now: T, ...options });
  return result;
};

describe("Content-Digest (RFC 9530)", () => {
  test("creates the RFC's sha-256 and sha-512 values", async () => {
    assert.strictEqual(await createContentDigest(BODY), SHA256);
    assert.strictEqual(
      await createContentDigest(BODY, { algorithms: "sha-512" }),
      SHA512
    );
    assert.strictEqual(
      await createContentDigest(BODY, { algorithms: ["sha-256", "sha-512"] }),
      `${SHA256}, ${SHA512}`
    );
  });

  test("accepts string, bytes, ArrayBuffer, views and Blob bodies", async () => {
    const bytes = new TextEncoder().encode(BODY);
    for (const body of [
      BODY,
      bytes,
      bytes.buffer,
      new DataView(bytes.buffer),
      new Blob([BODY]),
    ]) {
      assert.strictEqual(await createContentDigest(body), SHA256);
    }
  });

  test("rejects unsupported algorithms when creating", async () => {
    await assert.rejects(createContentDigest(BODY, { algorithms: "md5" }), /Unsupported/);
    await assert.rejects(createContentDigest(BODY, { algorithms: [] }), /At least one/);
  });

  test("verifies a matching body and reports the strongest algorithm", async () => {
    assert.deepStrictEqual(await verifyContentDigest(BODY, SHA256), {
      verified: true,
      algorithm: "sha-256",
    });
    assert.deepStrictEqual(await verifyContentDigest(BODY, `${SHA256}, ${SHA512}`), {
      verified: true,
      algorithm: "sha-512",
    });
    // the RFC 9421 test request's own header
    const r = await verifyContentDigest(BODY, TEST_REQUEST.headers["Content-Digest"]);
    assert.strictEqual(r.verified, true);
  });

  test("ignores unknown algorithms but needs at least one supported", async () => {
    const r = await verifyContentDigest(BODY, `md5=:AAAA:, ${SHA256}`);
    assert.deepStrictEqual(r, { verified: true, algorithm: "sha-256" });
    const none = await verifyContentDigest(BODY, "md5=:AAAA:");
    assert.strictEqual(none.verified, false);
    assert.strictEqual(none.reason, "No supported digest algorithm");
  });

  test("fails on a changed body", async () => {
    const r = await verifyContentDigest('{"hello": "World"}', SHA512);
    assert.deepStrictEqual(r, {
      verified: false,
      algorithm: "sha-512",
      reason: "Digest mismatch",
    });
  });

  test("fails when any supported digest present mismatches", async () => {
    const wrong256 = "sha-256=:" + btoa("x".repeat(32)) + ":";
    const r = await verifyContentDigest(BODY, `${wrong256}, ${SHA512}`);
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.algorithm, "sha-256");
  });

  test("respects an algorithms allowlist", async () => {
    const r = await verifyContentDigest(BODY, SHA256, { algorithms: ["sha-512"] });
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.reason, "No supported digest algorithm");
  });

  test("missing header, non-binary member, and garbage", async () => {
    assert.strictEqual((await verifyContentDigest(BODY, undefined)).reason, "No Content-Digest");
    assert.strictEqual((await verifyContentDigest(BODY, "")).reason, "No Content-Digest");
    const r = await verifyContentDigest(BODY, 'sha-256="abc"');
    assert.strictEqual(r.verified, false);
    assert.match(r.reason, /byte sequence/);
    await assert.rejects(verifyContentDigest(BODY, "sha-256=:::"));
  });

  test("DIGEST_ALGORITHMS lists sha-512 and sha-256", () => {
    assert.deepStrictEqual(Object.keys(DIGEST_ALGORITHMS), ["sha-512", "sha-256"]);
  });
});

describe("verifyMessage policy options", () => {
  test("defaults are unchanged: no created/tag/component/nonce checks", async () => {
    const msg = await signed({ created: T + 10_000, components: [] });
    assert.strictEqual((await verifyOne(msg)).verified, true);
  });

  test("requiredComponents accepts when covered", async () => {
    const r = await verifyOne(await signed(), {
      requiredComponents: ["@method", "Content-Digest"],
    });
    assert.strictEqual(r.verified, true, r.reason);
  });

  test("requiredComponents refuses a signature that covers nothing", async () => {
    const r = await verifyOne(await signed({ components: [] }), {
      requiredComponents: ["@method", "content-digest"],
    });
    assert.strictEqual(r.verified, false);
    assert.strictEqual(
      r.reason,
      'Missing required components: "@method" "content-digest"'
    );
  });

  test("requiredComponents compares identifier parameters", async () => {
    const msg = await signed({
      components: [{ id: "@query-param", params: { name: "Pet" } }],
    });
    const ok = await verifyOne(msg, {
      requiredComponents: [{ id: "@query-param", params: { name: "Pet" } }],
    });
    assert.strictEqual(ok.verified, true, ok.reason);
    const bad = await verifyOne(msg, {
      requiredComponents: [{ id: "@query-param", params: { name: "param" } }],
    });
    assert.strictEqual(bad.verified, false);
    assert.match(bad.reason, /Missing required components/);
  });

  test("tag must match when required", async () => {
    const msg = await signed({ tag: "p2pws" });
    assert.strictEqual((await verifyOne(msg, { tag: "p2pws" })).verified, true);
    assert.strictEqual((await verifyOne(msg, { tag: ["x", "p2pws"] })).verified, true);
    const wrong = await verifyOne(msg, { tag: "other" });
    assert.strictEqual(wrong.reason, "Tag mismatch");
    const missing = await verifyOne(await signed(), { tag: "p2pws" });
    assert.strictEqual(missing.verified, false);
    assert.strictEqual(missing.reason, "Tag mismatch");
  });

  test("maxAge accepts fresh signatures and refuses old ones", async () => {
    const msg = await signed();
    assert.strictEqual((await verifyOne(msg, { maxAge: 60, now: T + 60 })).verified, true);
    const old = await verifyOne(msg, { maxAge: 60, now: T + 61 });
    assert.strictEqual(old.reason, "Signature too old");
    const skewed = await verifyOne(msg, { maxAge: 60, clockSkew: 5, now: T + 65 });
    assert.strictEqual(skewed.verified, true, skewed.reason);
  });

  test("maxAge requires created", async () => {
    const r = await verifyOne(await signed({ created: null }), { maxAge: 60 });
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.reason, "Missing created parameter");
  });

  test("created in the future is refused once clockSkew or maxAge is set", async () => {
    const msg = await signed({ created: T + 30 });
    assert.strictEqual(
      (await verifyOne(msg, { clockSkew: 10 })).reason,
      "Signature created in the future"
    );
    assert.strictEqual(
      (await verifyOne(msg, { maxAge: 300 })).reason,
      "Signature created in the future"
    );
    assert.strictEqual((await verifyOne(msg, { clockSkew: 30 })).verified, true);
  });

  test("clockSkew extends expires tolerance; default stays strict", async () => {
    const msg = await signed({ expires: T + 10 });
    assert.strictEqual((await verifyOne(msg, { now: T + 11 })).reason, "Signature expired");
    assert.strictEqual((await verifyOne(msg, { now: T + 11, clockSkew: 1 })).verified, true);
    assert.strictEqual(
      (await verifyOne(msg, { now: T + 12, clockSkew: 1 })).reason,
      "Signature expired"
    );
  });

  test("invalid policy option values throw", async () => {
    const msg = await signed();
    await assert.rejects(verifyOne(msg, { maxAge: -1 }), /maxAge/);
    await assert.rejects(verifyOne(msg, { clockSkew: "5" }), /clockSkew/);
    await assert.rejects(verifyOne(msg, { checkNonce: "yes" }), /checkNonce/);
  });

  test("checkNonce (sync and async) gates acceptance and sees context", async () => {
    const seen = new Set();
    const checkNonce = async (nonce, ctx) => {
      assert.strictEqual(ctx.label, "sig1");
      assert.strictEqual(ctx.keyid, "test-key-ed25519");
      if (seen.has(nonce)) return false;
      seen.add(nonce);
      return true;
    };
    const msg = await signed({ nonce: "abc123" });
    assert.strictEqual((await verifyOne(msg, { checkNonce })).verified, true);
    const replay = await verifyOne(msg, { checkNonce });
    assert.strictEqual(replay.verified, false);
    assert.strictEqual(replay.reason, "Nonce rejected");
    assert.strictEqual(
      (await verifyOne(msg, { checkNonce: () => true })).verified,
      true
    );
    // only `true` counts as acceptance
    assert.strictEqual(
      (await verifyOne(msg, { checkNonce: () => "yes" })).reason,
      "Nonce rejected"
    );
  });

  test("checkNonce requires a nonce parameter", async () => {
    const r = await verifyOne(await signed(), { checkNonce: () => true });
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.reason, "Missing nonce");
  });

  test("checkNonce is not consulted for invalid signatures", async () => {
    const msg = await signed({ nonce: "n1" });
    msg.headers = { ...msg.headers, "Content-Digest": "sha-256=:AAAA:" };
    let called = false;
    const r = await verifyOne(msg, {
      checkNonce: () => {
        called = true;
        return true;
      },
    });
    assert.strictEqual(r.reason, "Signature mismatch");
    assert.strictEqual(called, false);
  });
});

describe("alg agreement (RFC 9421 §3.2)", () => {
  test("refuses when getKey's alg differs from the alg parameter", async () => {
    const msg = await signed({ includeAlg: true });
    const r = await verifyOne(msg, {
      getKey: () => ({ alg: "hmac-sha256", key: new Uint8Array(32) }),
    });
    assert.strictEqual(r.verified, false);
    assert.strictEqual(
      r.reason,
      "Algorithm mismatch: key is hmac-sha256, signature declares ed25519"
    );
  });

  test("accepts when they agree, or when only one side states it", async () => {
    const withAlg = await signed({ includeAlg: true });
    assert.strictEqual((await verifyOne(withAlg)).verified, true);
    // bare key: trust the signature's alg parameter
    assert.strictEqual(
      (await verifyOne(withAlg, { getKey: () => ED.publicJwk })).verified,
      true
    );
    // no alg parameter: getKey's alg is used
    assert.strictEqual((await verifyOne(await signed())).verified, true);
  });

  test("a bare JWK's JOSE alg member is not mistaken for an RFC 9421 alg", async () => {
    const msg = await signed({ includeAlg: true });
    const r = await verifyOne(msg, {
      getKey: () => ({ ...ED.publicJwk, alg: "EdDSA" }),
    });
    assert.strictEqual(r.verified, true, r.reason);
  });

  test("no alg anywhere is unsupported", async () => {
    const r = await verifyOne(await signed(), { getKey: () => ED.publicJwk });
    assert.strictEqual(r.verified, false);
    assert.strictEqual(r.reason, "Unsupported algorithm: undefined");
  });
});

describe("Fetch Request/Response adapters", () => {
  test("sign a Fetch Request and verify it, including Content-Digest", async () => {
    const request = new Request("https://example.com/foo?param=Value&Pet=dog", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: BODY,
    });
    request.headers.set("Content-Digest", await createContentDigest(await request.clone().text()));
    const { signatureInput, signature } = await signMessage(fromFetchRequest(request), {
      alg: "ed25519",
      key: ED.privateJwk,
      components: ["@method", "@target-uri", "content-digest"],
      created: T,
    });
    request.headers.set("Signature-Input", signatureInput);
    request.headers.set("Signature", signature);

    const [r] = await verifyMessage(fromFetchRequest(request), {
      getKey,
      now: T,
      requiredComponents: ["@method", "@target-uri", "content-digest"],
    });
    assert.strictEqual(r.verified, true, r.reason);
    const d = await verifyContentDigest(
      await request.arrayBuffer(),
      request.headers.get("content-digest")
    );
    assert.strictEqual(d.verified, true);
  });

  test("Response adapter binds ;req components to the related Request", async () => {
    const request = new Request("https://example.com/foo", { method: "POST" });
    const response = new Response("ok", {
      status: 201,
      headers: { "Content-Type": "text/plain" },
    });
    const message = fromFetchResponse(response, request);
    assert.strictEqual(message.status, 201);
    assert.strictEqual(message.request.method, "POST");
    const { signatureInput, signature } = await signMessage(message, {
      alg: "ed25519",
      key: ED.privateJwk,
      components: ["@status", { id: "@method", params: { req: true } }],
      created: T,
    });
    response.headers.set("Signature-Input", signatureInput);
    response.headers.set("Signature", signature);
    const [r] = await verifyMessage(fromFetchResponse(response, request), { getKey, now: T });
    assert.strictEqual(r.verified, true, r.reason);
    // a different request method breaks the binding
    const other = new Request("https://example.com/foo", { method: "PUT" });
    const [bad] = await verifyMessage(fromFetchResponse(response, other), { getKey, now: T });
    assert.strictEqual(bad.reason, "Signature mismatch");
    assert.strictEqual(fromFetchResponse(response).request, undefined);
  });
});
