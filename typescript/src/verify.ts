/**
 * ECDSA verification providers for the AlgoVoi RFC 9421 verifier (TypeScript).
 *
 * Byte-for-byte decision parity with the Python algovoi-rfc9421-ecdsa package.
 * Implements ecdsa-p256-sha256 (RFC 9421 3.3.5) and ecdsa-p384-sha384 (3.3.6):
 * raw r||s signatures (64 / 96 bytes, not DER), SHA-256 / SHA-384.
 *
 * Hardening before accepting a signature: point-on-curve validation, exact
 * signature length, r/s in [1, n-1], and optional canonical low-s enforcement
 * (off by default for spec interop).
 */
import { p256, p384 } from "@noble/curves/nist";
import { createHash } from "node:crypto";
import { VerifyError } from "@algovoi/rfc9421-verifier";

export class ECDSAError extends VerifyError {
  constructor(message: string) {
    super(message);
    // Cast is defensive: the published base type may not surface Error.name.
    (this as { name: string }).name = "ECDSAError";
  }
}

let strictLowS = false;

/** Enable/disable canonical low-s enforcement (anti-malleability). Off by default. */
export function setStrictLowS(enabled: boolean): void {
  strictLowS = !!enabled;
}

function toBytes(pk: string | Uint8Array): Uint8Array {
  if (typeof pk === "string") {
    const hex = pk.startsWith("0x") ? pk.slice(2) : pk;
    if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
      throw new ECDSAError("public_key hex is invalid");
    }
    return Uint8Array.from(Buffer.from(hex, "hex"));
  }
  return pk;
}

function makeVerifier(
  curve: typeof p256 | typeof p384,
  hashName: string,
  fieldSize: number,
) {
  const n = curve.CURVE.n;
  return (
    signingBase: string,
    signatureBytes: Uint8Array,
    publicKey: string | Uint8Array,
  ): boolean => {
    if (signatureBytes.length !== 2 * fieldSize) {
      throw new ECDSAError(
        `signature must be ${2 * fieldSize} bytes (r||s), got ${signatureBytes.length}`,
      );
    }
    const r = BigInt("0x" + Buffer.from(signatureBytes.slice(0, fieldSize)).toString("hex"));
    const s = BigInt("0x" + Buffer.from(signatureBytes.slice(fieldSize)).toString("hex"));
    if (!(r >= 1n && r < n && s >= 1n && s < n)) return false;
    if (strictLowS && s > n / 2n) return false;
    const pk = toBytes(publicKey);
    // Validate the public-key point is on the curve and not the identity, and
    // raise (parity with the Python provider) — noble's verify() returns false
    // for an invalid point rather than throwing, so we check explicitly.
    try {
      curve.ProjectivePoint.fromHex(pk);
    } catch (e) {
      throw new ECDSAError(`public key is not a valid point: ${(e as Error).message}`);
    }
    const msgHash = new Uint8Array(
      createHash(hashName).update(Buffer.from(signingBase, "utf8")).digest(),
    );
    // lowS:false — we do our own optional strict check above so default
    // behaviour matches the Python provider (accept high-s for interop).
    return curve.verify(signatureBytes, msgHash, pk, { lowS: false });
  };
}

export const verifyP256 = makeVerifier(p256, "sha256", 32);
export const verifyP384 = makeVerifier(p384, "sha384", 48);
