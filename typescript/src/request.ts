/**
 * Pure-wrapper RFC 9421 request verification with ECDSA support (TypeScript).
 *
 * Does NOT modify the core verifier. Ed25519 requests are delegated verbatim to
 * the untouched @algovoi/rfc9421-verifier; ECDSA requests reuse the core's
 * hardened primitives (parsing, freshness, content-digest, signing-base,
 * downgrade/allow-list) and add only the ECDSA signature check.
 */
import {
  VerifyError,
  verifyRequest as coreVerifyRequest,
  parseSignatureInput,
  parseSignatureValue,
  buildSigningBase,
  verifyContentDigest,
  checkFreshness,
  SignatureInputParseError,
  SigningBaseError,
  ContentDigestError,
  FreshnessError,
  type VerifyResult,
  type VerifyRequestInput,
} from "@algovoi/rfc9421-verifier";
import { ECDSAError, verifyP256, verifyP384 } from "./verify.js";

const ECDSA: Record<
  string,
  (b: string, s: Uint8Array, p: string | Uint8Array) => boolean
> = {
  "ecdsa-p256-sha256": verifyP256,
  "ecdsa-p384-sha384": verifyP384,
};

export const DEFAULT_ALLOWED = [
  "ed25519",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
];

function newResult(): VerifyResult {
  return {
    valid: false,
    signature_valid: false,
    content_digest_valid: false,
    signing_base: "",
    covered_components: [],
    parameters: {},
    label: "",
    errors: [],
  };
}

function fail(r: VerifyResult, msg: string): VerifyResult {
  r.errors.push(msg);
  r.valid = false;
  return r;
}

function bodyToBytes(body: Uint8Array | Buffer | string): Uint8Array {
  if (typeof body === "string") return new TextEncoder().encode(body);
  return body instanceof Uint8Array ? body : new Uint8Array(body);
}

export async function verifyRequest(
  input: VerifyRequestInput,
): Promise<VerifyResult> {
  const norm: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers)) norm[k.toLowerCase()] = v;

  const si = norm["signature-input"];
  if (!si) return fail(newResult(), "Signature-Input header missing");
  let parsed;
  try {
    parsed = parseSignatureInput(si);
  } catch (e) {
    if (e instanceof SignatureInputParseError)
      return fail(newResult(), `Signature-Input parse error: ${e.message}`);
    throw e;
  }
  const alg = parsed.parameters["alg"];
  const allowed = input.allowedAlgorithms ?? DEFAULT_ALLOWED;

  // Ed25519 -> delegate entirely to the untouched core verifier.
  if (typeof alg === "string" && alg.toLowerCase() === "ed25519") {
    return coreVerifyRequest({ ...input, allowedAlgorithms: allowed });
  }

  // ECDSA path: reuse the core's hardened primitives.
  const result = newResult();
  result.label = parsed.label;
  result.covered_components = parsed.covered_components;
  result.parameters = parsed.parameters;

  const sValue = norm["signature"];
  if (!sValue) return fail(result, "Signature header missing");
  let sigParsed;
  try {
    sigParsed = parseSignatureValue(sValue);
  } catch (e) {
    if (e instanceof SignatureInputParseError)
      return fail(result, `Signature parse error: ${e.message}`);
    throw e;
  }
  if (sigParsed.label && parsed.label && sigParsed.label !== parsed.label) {
    return fail(
      result,
      `Signature label ${sigParsed.label} does not match Signature-Input label ${parsed.label}`,
    );
  }

  const now = input.now ?? Math.floor(Date.now() / 1000);
  const mode = input.mode ?? "rfc9421";
  try {
    checkFreshness(parsed.parameters, parsed.covered_components, {
      now,
      maxAgeSeconds: input.maxAgeSeconds,
      maxSkewSeconds: input.maxSkewSeconds,
      enforceExpires: input.enforceExpires,
      requireCreated: input.requireCreated,
      paramsSigned: mode === "rfc9421",
    });
  } catch (e) {
    if (e instanceof FreshnessError)
      return fail(result, `Freshness check failed: ${e.message}`);
    throw e;
  }

  const tagValue = parsed.parameters["tag"];
  if (input.requireTag && tagValue === undefined)
    return fail(result, "Signature 'tag' parameter required but absent");
  if (
    input.expectedTag !== undefined &&
    input.expectedTag !== null &&
    tagValue !== input.expectedTag
  ) {
    return fail(
      result,
      `Signature 'tag' ${JSON.stringify(tagValue)} does not match expected ${JSON.stringify(input.expectedTag)}`,
    );
  }

  const requireCd = input.requireContentDigest ?? true;
  const requireAlg =
    input.requireAlgorithm == null ? undefined : input.requireAlgorithm;
  if (requireCd) {
    const cd = norm["content-digest"];
    if (!cd) return fail(result, "Content-Digest header required but missing");
    try {
      verifyContentDigest(bodyToBytes(input.body), cd, requireAlg);
      result.content_digest_valid = true;
    } catch (e) {
      if (e instanceof ContentDigestError)
        return fail(result, `Content-Digest verification failed: ${e.message}`);
      throw e;
    }
  } else {
    result.content_digest_valid = true;
  }

  let signingBase: string;
  try {
    signingBase = buildSigningBase({
      coveredComponents: parsed.covered_components,
      method: input.method,
      authority: input.authority,
      path: input.path,
      scheme: input.scheme ?? "https",
      headers: norm,
      parameters: parsed.parameters,
      mode,
      signatureParamsRaw: mode === "rfc9421" ? parsed.params_block : undefined,
    });
  } catch (e) {
    if (e instanceof SigningBaseError)
      return fail(result, `Signing-base build error: ${e.message}`);
    throw e;
  }
  result.signing_base = signingBase;

  // Algorithm-downgrade hardening: reject missing alg; pin to allow-list.
  if (alg === undefined)
    return fail(result, "Signature-Input missing 'alg' parameter");
  if (typeof alg !== "string")
    return fail(result, `Signature-Input 'alg' parameter must be string, got ${typeof alg}`);
  const allowedLower = new Set([...allowed].map((a) => String(a).toLowerCase()));
  if (!allowedLower.has(alg.toLowerCase())) {
    return fail(
      result,
      `Signature algorithm ${JSON.stringify(alg)} is not in the allowed set [${[...allowedLower].sort().map((s) => JSON.stringify(s)).join(", ")}]`,
    );
  }

  const verifier = ECDSA[alg.toLowerCase()];
  if (!verifier) return fail(result, `no ECDSA verifier available for algorithm ${alg}`);
  let sigOk: boolean;
  try {
    sigOk = verifier(signingBase, sigParsed.signature, input.publicKey);
  } catch (e) {
    if (e instanceof VerifyError)
      return fail(result, `Signature verification setup error: ${e.message}`);
    throw e;
  }
  if (!sigOk)
    return fail(result, "ECDSA signature does not verify against signing base");
  result.signature_valid = true;

  if (input.nonceSeen) {
    const nonceValue = parsed.parameters["nonce"];
    if (nonceValue !== undefined) {
      const keyidValue = String(parsed.parameters["keyid"] ?? "");
      let already: boolean;
      try {
        already = input.nonceSeen(String(nonceValue), keyidValue);
      } catch (e) {
        return fail(result, `Nonce store check errored: ${(e as Error).message}`);
      }
      if (already)
        return fail(result, "Signature nonce has already been used (replay)");
    }
  }

  result.valid = result.signature_valid && result.content_digest_valid;
  return result;
}
