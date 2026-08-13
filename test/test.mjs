import { test, describe } from "node:test";
import assert from "node:assert";
import {
  createSignatureBase,
  parseSignatureHeaders,
  signBase,
  verifyBase,
  signMessage,
  verifyMessage,
} from "../index.mjs";
import {
  KEYS,
  sharedSecretBytes,
  TEST_REQUEST,
  TEST_RESPONSE,
  SIGNATURES,
} from "./vectors.mjs";

const b64ToBytes = (b64) => {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
};

const bytesToB64 = (bytes) => {
  let bin = "";
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin);
};

// RFC 9421 Appendix B.2 covered components and parameters per test case
const CASES = {
  b21: {
    message: TEST_REQUEST,
    components: [],
    params: {
      created: 1618884473,
      keyid: "test-key-rsa-pss",
      nonce: "b3k2pp5k7z-50gnwp.yemd",
    },
    base: `"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"`,
  },
  b22: {
    message: TEST_REQUEST,
    components: [
      "@authority",
      "content-digest",
      { id: "@query-param", params: { name: "Pet" } },
    ],
    params: {
      created: 1618884473,
      keyid: "test-key-rsa-pss",
      tag: "header-example",
    },
    base: [
      `"@authority": example.com`,
      `"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:`,
      `"@query-param";name="Pet": dog`,
      `"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"`,
    ].join("\n"),
  },
  b23: {
    message: TEST_REQUEST,
    components: [
      "date",
      "@method",
      "@path",
      "@query",
      "@authority",
      "content-type",
      "content-digest",
      "content-length",
    ],
    params: { created: 1618884473, keyid: "test-key-rsa-pss" },
    base: [
      `"date": Tue, 20 Apr 2021 02:07:55 GMT`,
      `"@method": POST`,
      `"@path": /foo`,
      `"@query": ?param=Value&Pet=dog`,
      `"@authority": example.com`,
      `"content-type": application/json`,
      `"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:`,
      `"content-length": 18`,
      `"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"`,
    ].join("\n"),
  },
  b24: {
    message: TEST_RESPONSE,
    components: ["@status", "content-type", "content-digest", "content-length"],
    params: { created: 1618884473, keyid: "test-key-ecc-p256" },
    base: [
      `"@status": 200`,
      `"content-type": application/json`,
      `"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:`,
      `"content-length": 23`,
      `"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"`,
    ].join("\n"),
  },
  b25: {
    message: TEST_REQUEST,
    components: ["date", "@authority", "content-type"],
    params: { created: 1618884473, keyid: "test-shared-secret" },
    base: [
      `"date": Tue, 20 Apr 2021 02:07:55 GMT`,
      `"@authority": example.com`,
      `"content-type": application/json`,
      `"@signature-params": ("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`,
    ].join("\n"),
  },
  b26: {
    message: TEST_REQUEST,
    components: [
      "date",
      "@method",
      "@path",
      "@authority",
      "content-type",
      "content-length",
    ],
    params: { created: 1618884473, keyid: "test-key-ed25519" },
    base: [
      `"date": Tue, 20 Apr 2021 02:07:55 GMT`,
      `"@method": POST`,
      `"@path": /foo`,
      `"@authority": example.com`,
      `"content-type": application/json`,
      `"content-length": 18`,
      `"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`,
    ].join("\n"),
  },
};

describe("RFC 9421 signature base construction (Appendix B.2)", () => {
  for (const [name, c] of Object.entries(CASES)) {
    test(`B.2.${name.slice(1)} signature base matches the RFC`, () => {
      const { base } = createSignatureBase(c.message, c.components, c.params);
      assert.strictEqual(base, c.base);
    });
  }
});

describe("RFC 9421 signature verification (Appendix B.2)", () => {
  test("B.2.1 minimal rsa-pss-sha512 signature verifies", async () => {
    const c = CASES.b21;
    const { base } = createSignatureBase(c.message, c.components, c.params);
    assert.strictEqual(
      await verifyBase(
        "rsa-pss-sha512",
        KEYS["test-key-rsa-pss"].publicJwk,
        b64ToBytes(SIGNATURES["sig-b21"]),
        base
      ),
      true
    );
  });

  test("B.2.2 selective rsa-pss-sha512 signature verifies", async () => {
    const c = CASES.b22;
    const { base } = createSignatureBase(c.message, c.components, c.params);
    assert.strictEqual(
      await verifyBase(
        "rsa-pss-sha512",
        KEYS["test-key-rsa-pss"].publicJwk,
        b64ToBytes(SIGNATURES["sig-b22"]),
        base
      ),
      true
    );
  });

  test("B.2.3 full-coverage rsa-pss-sha512 signature verifies", async () => {
    const c = CASES.b23;
    const { base } = createSignatureBase(c.message, c.components, c.params);
    assert.strictEqual(
      await verifyBase(
        "rsa-pss-sha512",
        KEYS["test-key-rsa-pss"].publicJwk,
        b64ToBytes(SIGNATURES["sig-b23"]),
        base
      ),
      true
    );
  });

  test("B.2.4 ecdsa-p256-sha256 response signature verifies", async () => {
    const c = CASES.b24;
    const { base } = createSignatureBase(c.message, c.components, c.params);
    assert.strictEqual(
      await verifyBase(
        "ecdsa-p256-sha256",
        KEYS["test-key-ecc-p256"].publicJwk,
        b64ToBytes(SIGNATURES["sig-b24"]),
        base
      ),
      true
    );
  });

  test("B.2.5 hmac-sha256 signing is byte-exact", async () => {
    const c = CASES.b25;
    const { base } = createSignatureBase(c.message, c.components, c.params);
    const sig = await signBase("hmac-sha256", sharedSecretBytes(), base);
    assert.strictEqual(bytesToB64(sig), SIGNATURES["sig-b25"]);
  });

  test("B.2.6 ed25519 signing is byte-exact", async () => {
    const c = CASES.b26;
    const { base } = createSignatureBase(c.message, c.components, c.params);
    const sig = await signBase(
      "ed25519",
      KEYS["test-key-ed25519"].privateJwk,
      base
    );
    assert.strictEqual(bytesToB64(sig), SIGNATURES["sig-b26"]);
  });
});

describe("High-level sign/verify", () => {
  test("signMessage reproduces the RFC's B.2.6 headers exactly", async () => {
    const c = CASES.b26;
    const result = await signMessage(TEST_REQUEST, {
      alg: "ed25519",
      key: KEYS["test-key-ed25519"].privateJwk,
      label: "sig-b26",
      components: c.components,
      created: 1618884473,
      keyid: "test-key-ed25519",
    });
    assert.strictEqual(
      result.signatureInput,
      `sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"`
    );
    assert.strictEqual(
      result.signature,
      `sig-b26=:${SIGNATURES["sig-b26"]}:`
    );
  });

  test("signMessage reproduces the RFC's B.2.5 HMAC headers exactly", async () => {
    const c = CASES.b25;
    const result = await signMessage(TEST_REQUEST, {
      alg: "hmac-sha256",
      key: sharedSecretBytes(),
      label: "sig-b25",
      components: c.components,
      created: 1618884473,
      keyid: "test-shared-secret",
    });
    assert.strictEqual(
      result.signatureInput,
      `sig-b25=("date" "@authority" "content-type");created=1618884473;keyid="test-shared-secret"`
    );
    assert.strictEqual(result.signature, `sig-b25=:${SIGNATURES["sig-b25"]}:`);
  });

  const roundTrip = async (alg, keyName, message, components) => {
    const keys = KEYS[keyName];
    const signingKey =
      alg === "hmac-sha256" ? sharedSecretBytes() : keys.privateJwk;
    const verifyKey =
      alg === "hmac-sha256" ? sharedSecretBytes() : keys.publicJwk;

    const { signatureInput, signature } = await signMessage(message, {
      alg,
      key: signingKey,
      components,
      created: 1618884473,
      keyid: keyName,
    });
    const signed = {
      ...message,
      headers: {
        ...message.headers,
        "Signature-Input": signatureInput,
        Signature: signature,
      },
    };
    return verifyMessage(signed, {
      getKey: ({ keyid }) => {
        assert.strictEqual(keyid, keyName);
        return { alg, key: verifyKey };
      },
    });
  };

  for (const [alg, keyName] of [
    ["rsa-pss-sha512", "test-key-rsa-pss"],
    ["ecdsa-p256-sha256", "test-key-ecc-p256"],
    ["ed25519", "test-key-ed25519"],
    ["hmac-sha256", "test-shared-secret"],
  ]) {
    test(`round-trips ${alg}`, async () => {
      const results = await roundTrip(alg, keyName, TEST_REQUEST, [
        "@method",
        "@authority",
        "content-type",
      ]);
      assert.strictEqual(results.length, 1);
      assert.strictEqual(results[0].verified, true, results[0].reason);
    });
  }

  test("verifyMessage detects tampering", async () => {
    const { signatureInput, signature } = await signMessage(TEST_REQUEST, {
      alg: "ed25519",
      key: KEYS["test-key-ed25519"].privateJwk,
      components: ["@method", "content-type"],
      created: 1618884473,
      keyid: "test-key-ed25519",
    });
    const tampered = {
      ...TEST_REQUEST,
      headers: {
        ...TEST_REQUEST.headers,
        "Content-Type": "text/plain",
        "Signature-Input": signatureInput,
        Signature: signature,
      },
    };
    const results = await verifyMessage(tampered, {
      getKey: () => ({
        alg: "ed25519",
        key: KEYS["test-key-ed25519"].publicJwk,
      }),
    });
    assert.strictEqual(results[0].verified, false);
    assert.strictEqual(results[0].reason, "Signature mismatch");
  });

  test("verifyMessage rejects expired signatures", async () => {
    const { signatureInput, signature } = await signMessage(TEST_REQUEST, {
      alg: "hmac-sha256",
      key: sharedSecretBytes(),
      components: ["@method"],
      created: 1618884473,
      expires: 1618884773,
      keyid: "test-shared-secret",
    });
    const signed = {
      ...TEST_REQUEST,
      headers: {
        ...TEST_REQUEST.headers,
        "Signature-Input": signatureInput,
        Signature: signature,
      },
    };
    const results = await verifyMessage(signed, {
      getKey: () => ({ alg: "hmac-sha256", key: sharedSecretBytes() }),
      now: 1618884774,
    });
    assert.strictEqual(results[0].verified, false);
    assert.strictEqual(results[0].reason, "Signature expired");
  });
});

describe("Signature header parsing", () => {
  test("parses Signature-Input and Signature dictionaries", () => {
    const entries = parseSignatureHeaders(
      `sig1=("@method" "@query-param";name="Pet");created=1618884473;keyid="k1"`,
      `sig1=:${SIGNATURES["sig-b25"]}:`
    );
    assert.deepStrictEqual(entries.sig1.components, [
      { id: "@method", params: {} },
      { id: "@query-param", params: { name: "Pet" } },
    ]);
    assert.deepStrictEqual(entries.sig1.params, {
      created: 1618884473,
      keyid: "k1",
    });
    assert.ok(entries.sig1.signature instanceof Uint8Array);
  });
});

describe("Component edge cases", () => {
  test("@query is '?' when the URL has no query", () => {
    const { base } = createSignatureBase(
      { method: "GET", url: "https://example.com/path", headers: {} },
      ["@query"],
      {}
    );
    assert.ok(base.startsWith(`"@query": ?\n`));
  });

  test("multiple header values are combined with comma-space", () => {
    const { base } = createSignatureBase(
      {
        method: "GET",
        url: "https://example.com/",
        headers: [
          ["X-List", "a"],
          ["X-List", "b, c"],
        ],
      },
      ["x-list"],
      {}
    );
    assert.ok(base.startsWith(`"x-list": a, b, c\n`));
  });

  test("dictionary member selection with ;key", () => {
    const { base } = createSignatureBase(
      {
        method: "GET",
        url: "https://example.com/",
        headers: { "Example-Dict": " a=1, b=2;x=1;y=2, c=(a b c)" },
      },
      [{ id: "example-dict", params: { key: "b" } }],
      {}
    );
    assert.ok(base.startsWith(`"example-dict";key="b": 2;x=1;y=2\n`));
  });

  test("byte-sequence wrapping with ;bs", () => {
    const { base } = createSignatureBase(
      {
        method: "GET",
        url: "https://example.com/",
        headers: { "X-Raw": "value" },
      },
      [{ id: "x-raw", params: { bs: true } }],
      {}
    );
    assert.ok(base.startsWith(`"x-raw";bs: :dmFsdWU=:\n`));
  });

  test(";req pulls components from the related request", () => {
    const { base } = createSignatureBase(
      { ...TEST_RESPONSE, request: TEST_REQUEST },
      ["@status", { id: "@method", params: { req: true } }],
      {}
    );
    assert.ok(base.includes(`"@method";req: POST\n`));
  });

  test("missing fields and duplicate components throw", () => {
    assert.throws(() =>
      createSignatureBase(TEST_REQUEST, ["missing-header"], {})
    );
    assert.throws(() =>
      createSignatureBase(TEST_REQUEST, ["@method", "@method"], {})
    );
  });
});
