import { describe, it, expect } from "vitest";
import { p256 } from "@noble/curves/nist";
import { createHash } from "node:crypto";
import { ECDSAError, setStrictLowS, verifyP256, verifyRequest } from "../src/index.js";
import {
  buildSigningBase,
  parseSignatureInput,
  computeContentDigest,
} from "@algovoi/rfc9421-verifier";

const BASE = '"@method": POST\n"@path": /a2a\n"@signature-params": ("@method" "@path")';
const N = p256.CURVE.n;

function key() {
  const sk = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(sk, false);
  return { sk, pub };
}
function raw(sk: Uint8Array, base = BASE): Uint8Array {
  const h = new Uint8Array(createHash("sha256").update(Buffer.from(base, "utf8")).digest());
  return p256.sign(h, sk, { lowS: true }).toCompactRawBytes();
}

describe("ecdsa provider (raw)", () => {
  it("accepts a valid signature", () => {
    const { sk, pub } = key();
    expect(verifyP256(BASE, raw(sk), pub)).toBe(true);
  });
  it("rejects tampered base", () => {
    const { sk, pub } = key();
    expect(verifyP256(BASE + "x", raw(sk), pub)).toBe(false);
  });
  it("rejects flipped signature", () => {
    const { sk, pub } = key();
    const s = Uint8Array.from(raw(sk)); s[0] ^= 1;
    expect(verifyP256(BASE, s, pub)).toBe(false);
  });
  it("throws on wrong length", () => {
    const { pub } = key();
    expect(() => verifyP256(BASE, new Uint8Array(63), pub)).toThrow(ECDSAError);
  });
  it("rejects zero r/s", () => {
    const { pub } = key();
    expect(verifyP256(BASE, new Uint8Array(64), pub)).toBe(false);
  });
  it("throws on invalid point", () => {
    const { sk } = key();
    const bad = new Uint8Array(65); bad[0] = 0x04;
    expect(() => verifyP256(BASE, raw(sk), bad)).toThrow(ECDSAError);
  });
  it("strict low-s rejects high-s", () => {
    const { sk, pub } = key();
    const h = new Uint8Array(createHash("sha256").update(Buffer.from(BASE, "utf8")).digest());
    const low = p256.sign(h, sk, { lowS: true });
    const high = new p256.Signature(low.r, N - low.s).toCompactRawBytes();
    expect(verifyP256(BASE, high, pub)).toBe(true);
    setStrictLowS(true);
    try { expect(verifyP256(BASE, high, pub)).toBe(false); }
    finally { setStrictLowS(false); }
  });
});

describe("verifyRequest (wrapper, ECDSA path)", () => {
  function signedReq(sk: Uint8Array, body = '{"x":1}') {
    const cd = computeContentDigest(new TextEncoder().encode(body));
    const params =
      '("@method" "@path" "content-digest");created=1750000000;keyid="k";alg="ecdsa-p256-sha256"';
    const si = `sig=${params}`;
    const parsed = parseSignatureInput(si);
    const base = buildSigningBase({
      coveredComponents: parsed.covered_components,
      method: "POST", authority: "api.x", path: "/a2a", scheme: "https",
      headers: { "content-digest": cd }, parameters: parsed.parameters,
      mode: "rfc9421", signatureParamsRaw: parsed.params_block,
    });
    const sig = raw(sk, base);
    return {
      "signature-input": si,
      signature: "sig=:" + Buffer.from(sig).toString("base64") + ":",
      "content-digest": cd,
    };
  }

  it("accepts a valid ECDSA request end-to-end", async () => {
    const { sk, pub } = key();
    const r = await verifyRequest({
      method: "POST", authority: "api.x", path: "/a2a",
      headers: signedReq(sk), body: Buffer.from('{"x":1}'), publicKey: pub,
      allowedAlgorithms: ["ecdsa-p256-sha256"],
    });
    expect(r.valid).toBe(true);
    expect(r.signature_valid).toBe(true);
  });

  it("rejects when ECDSA not in allow-list", async () => {
    const { sk, pub } = key();
    const r = await verifyRequest({
      method: "POST", authority: "api.x", path: "/a2a",
      headers: signedReq(sk), body: Buffer.from('{"x":1}'), publicKey: pub,
      allowedAlgorithms: ["ed25519"],
    });
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /not in the allowed set/.test(e))).toBe(true);
  });

  it("rejects a tampered body", async () => {
    const { sk, pub } = key();
    const r = await verifyRequest({
      method: "POST", authority: "api.x", path: "/a2a",
      headers: signedReq(sk), body: Buffer.from('{"x":2}'), publicKey: pub,
      allowedAlgorithms: ["ecdsa-p256-sha256"],
    });
    expect(r.valid).toBe(false);
  });
});
