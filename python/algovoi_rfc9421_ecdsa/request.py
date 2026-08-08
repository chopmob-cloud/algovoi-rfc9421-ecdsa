"""Pure-wrapper RFC 9421 request verification with ECDSA support.

This does NOT modify or re-publish the core verifier. Ed25519 requests are
delegated verbatim to the untouched `algovoi-rfc9421-verifier` (0.4.2+); ECDSA
requests reuse the core's already-hardened primitives (Signature-Input parsing,
freshness, Content-Digest, signing-base construction, downgrade/allow-list) and
add only the ECDSA signature check. The verifier package is never touched.
"""
from __future__ import annotations

import time
from typing import Callable

from algovoi_rfc9421_verifier import (
    VerifyResult,
    build_signing_base,
    check_freshness,
    parse_signature_input,
    parse_signature_value,
    verify_content_digest,
    verify_request as _core_verify_request,
)
from algovoi_rfc9421_verifier.content_digest import ContentDigestError
from algovoi_rfc9421_verifier.freshness import FreshnessError
from algovoi_rfc9421_verifier.parse import SignatureInputParseError
from algovoi_rfc9421_verifier.signing_base import SigningBaseError

from algovoi_rfc9421_ecdsa.verify import ECDSAError, verify_p256, verify_p384

_ECDSA_VERIFIERS: dict[str, Callable] = {
    "ecdsa-p256-sha256": verify_p256,
    "ecdsa-p384-sha384": verify_p384,
}

#: Default accepted algorithms: Ed25519 (via core) plus the ECDSA suites.
DEFAULT_ALLOWED = frozenset(
    {"ed25519", "ecdsa-p256-sha256", "ecdsa-p384-sha384"}
)


def verify_request(
    *,
    method: str,
    authority: str,
    path: str,
    headers: dict,
    body: bytes,
    public_key,
    scheme: str = "https",
    require_content_digest: bool = True,
    require_algorithm: str | None = None,
    mode: str = "rfc9421",
    now: int | None = None,
    max_age_seconds: int | None = None,
    max_skew_seconds: int = 60,
    enforce_expires: bool = True,
    require_created: bool = False,
    expected_tag: str | None = None,
    require_tag: bool = False,
    allowed_algorithms=DEFAULT_ALLOWED,
    nonce_seen: Callable[[str, str], bool] | None = None,
) -> VerifyResult:
    """Verify an RFC 9421 request signed with Ed25519 or ECDSA (P-256/P-384).

    Same signature and semantics as the core verify_request, extended to ECDSA.
    """
    norm = {k.lower(): v for k, v in headers.items()}
    si_value = norm.get("signature-input")
    if not si_value:
        return VerifyResult().fail("Signature-Input header missing")
    try:
        parsed = parse_signature_input(si_value)
    except SignatureInputParseError as e:
        return VerifyResult().fail(f"Signature-Input parse error: {e}")

    alg = parsed.parameters.get("alg")

    # Ed25519 -> delegate entirely to the untouched core verifier (no duplication).
    if isinstance(alg, str) and alg.lower() == "ed25519":
        return _core_verify_request(
            method=method, authority=authority, path=path, headers=headers,
            body=body, public_key=public_key, scheme=scheme,
            require_content_digest=require_content_digest,
            require_algorithm=require_algorithm, mode=mode, now=now,
            max_age_seconds=max_age_seconds, max_skew_seconds=max_skew_seconds,
            enforce_expires=enforce_expires, require_created=require_created,
            expected_tag=expected_tag, require_tag=require_tag,
            allowed_algorithms=allowed_algorithms, nonce_seen=nonce_seen,
        )

    # ECDSA path: reuse the core's hardened primitives, add the ECDSA check.
    result = VerifyResult()
    result.label = parsed.label
    result.covered_components = parsed.covered_components
    result.parameters = parsed.parameters

    s_value = norm.get("signature")
    if not s_value:
        return result.fail("Signature header missing")
    try:
        s_label, sig_bytes = parse_signature_value(s_value)
    except SignatureInputParseError as e:
        return result.fail(f"Signature parse error: {e}")
    if s_label and parsed.label and s_label != parsed.label:
        return result.fail(
            f"Signature label {s_label!r} does not match Signature-Input "
            f"label {parsed.label!r}"
        )

    ts_now = now if now is not None else int(time.time())
    try:
        check_freshness(
            parsed.parameters, parsed.covered_components, now=ts_now,
            max_age_seconds=max_age_seconds, max_skew_seconds=max_skew_seconds,
            enforce_expires=enforce_expires, require_created=require_created,
            params_signed=(mode == "rfc9421"),
        )
    except FreshnessError as e:
        return result.fail(f"Freshness check failed: {e}")

    tag_value = parsed.parameters.get("tag")
    if require_tag and tag_value is None:
        return result.fail("Signature 'tag' parameter required but absent")
    if expected_tag is not None and tag_value != expected_tag:
        return result.fail(
            f"Signature 'tag' {tag_value!r} does not match expected {expected_tag!r}"
        )

    if require_content_digest:
        cd = norm.get("content-digest")
        if not cd:
            return result.fail("Content-Digest header required but missing")
        try:
            verify_content_digest(body, cd, require_algorithm=require_algorithm)
            result.content_digest_valid = True
        except ContentDigestError as e:
            return result.fail(f"Content-Digest verification failed: {e}")
    else:
        result.content_digest_valid = True

    try:
        signing_base = build_signing_base(
            parsed.covered_components, method=method, authority=authority,
            path=path, scheme=scheme, headers=norm, parameters=parsed.parameters,
            mode=mode,
            signature_params_raw=(parsed.params_block if mode == "rfc9421" else None),
        )
    except SigningBaseError as e:
        return result.fail(f"Signing-base build error: {e}")
    result.signing_base = signing_base

    # Algorithm-downgrade hardening: reject a missing alg; pin to the allow-list.
    if alg is None:
        return result.fail("Signature-Input missing 'alg' parameter")
    if not isinstance(alg, str):
        return result.fail(
            f"Signature-Input 'alg' parameter must be string, got {type(alg).__name__}"
        )
    if alg.lower() not in {a.lower() for a in allowed_algorithms}:
        return result.fail(
            f"Signature algorithm {alg!r} is not in the allowed set "
            f"{sorted(allowed_algorithms)}"
        )

    verifier = _ECDSA_VERIFIERS.get(alg.lower())
    if verifier is None:
        return result.fail(f"no ECDSA verifier available for algorithm {alg!r}")
    try:
        sig_ok = verifier(signing_base, bytes(sig_bytes), public_key)
    except ECDSAError as e:
        return result.fail(f"Signature verification setup error: {e}")
    if not sig_ok:
        return result.fail("ECDSA signature does not verify against signing base")
    result.signature_valid = True

    if nonce_seen is not None:
        nonce_value = parsed.parameters.get("nonce")
        if nonce_value is not None:
            keyid_value = str(parsed.parameters.get("keyid", ""))
            try:
                already = nonce_seen(str(nonce_value), keyid_value)
            except Exception as e:  # a store failure fails closed
                return result.fail(f"Nonce store check errored: {e}")
            if already:
                return result.fail("Signature nonce has already been used (replay)")

    result.valid = result.signature_valid and result.content_digest_valid
    return result


__all__ = ["verify_request", "DEFAULT_ALLOWED"]
