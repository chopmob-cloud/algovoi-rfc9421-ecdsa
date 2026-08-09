/**
 * @algovoi/rfc9421-ecdsa: ECDSA (P-256/P-384) add-on for @algovoi/rfc9421-verifier.
 *
 * A PURE add-on: it does not modify the core verifier. Use verifyRequest for a
 * drop-in that accepts Ed25519 (delegated to the untouched verifier) plus the
 * RFC 9421 ECDSA suites `ecdsa-p256-sha256` and `ecdsa-p384-sha384`.
 *
 * Apache-2.0.
 */
export { verifyRequest, DEFAULT_ALLOWED } from "./request.js";
export { ECDSAError, setStrictLowS, verifyP256, verifyP384 } from "./verify.js";
