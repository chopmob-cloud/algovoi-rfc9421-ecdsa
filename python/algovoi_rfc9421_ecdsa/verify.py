"""ECDSA verification providers for the AlgoVoi RFC 9421 verifier.

Implements the two RFC 9421-registered ECDSA algorithms:
  - ecdsa-p256-sha256 (RFC 9421 3.3.5): P-256, SHA-256, 64-byte r||s signature
  - ecdsa-p384-sha384 (RFC 9421 3.3.6): P-384, SHA-384, 96-byte r||s signature

RFC 9421 carries the signature as the raw big-endian concatenation r||s (each
component field-element-sized), NOT DER. Public keys are supplied out of band as
SEC1 point bytes (compressed or uncompressed) or hex.

Hardening applied before accepting a signature:
  - the public-key point must be on the curve and not the identity
    (from_encoded_point rejects off-curve / malformed points);
  - the signature length must match the curve exactly (64 / 96 bytes);
  - r and s must each be in [1, n-1] (reject zero / out-of-range);
  - optional low-s (canonical) enforcement to defeat signature malleability,
    controlled by set_strict_low_s() (default off for spec interop).

This package depends on `cryptography`; the core verifier stays PyNaCl-only.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from algovoi_rfc9421_verifier import VerifyError


class ECDSAError(VerifyError):
    """Raised on an ECDSA setup error (bad key/signature shape)."""


# Curve subgroup orders (n). Used for r/s range and low-s checks.
_N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_N_P384 = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "C7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
    16,
)

_strict_low_s = False


def set_strict_low_s(enabled: bool) -> None:
    """Enable/disable canonical low-s enforcement (anti-malleability).

    Off by default: standard ECDSA signers may emit high-s and stay RFC 9421
    compliant. Turn on for deployments that require a single canonical signature.
    """
    global _strict_low_s
    _strict_low_s = bool(enabled)


def _coerce_pubkey(public_key, curve) -> ec.EllipticCurvePublicKey:
    if isinstance(public_key, str):
        raw = public_key[2:] if public_key.startswith("0x") else public_key
        try:
            data = bytes.fromhex(raw)
        except ValueError as e:
            raise ECDSAError(f"public_key hex is invalid: {e}") from e
    elif isinstance(public_key, (bytes, bytearray)):
        data = bytes(public_key)
    else:
        raise ECDSAError(
            f"public_key must be SEC1 point bytes or hex, got {type(public_key).__name__}"
        )
    try:
        # from_encoded_point validates the point is on the curve (and not identity).
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)
    except ValueError as e:
        raise ECDSAError(f"public_key is not a valid point on {curve.name}: {e}") from e


def _make_verifier(curve, hash_alg, field_size: int, order: int):
    def _verify(signing_base: str, signature_bytes: bytes, public_key) -> bool:
        if len(signature_bytes) != 2 * field_size:
            raise ECDSAError(
                f"{curve.name} signature must be {2 * field_size} bytes (r||s), "
                f"got {len(signature_bytes)}"
            )
        r = int.from_bytes(signature_bytes[:field_size], "big")
        s = int.from_bytes(signature_bytes[field_size:], "big")
        # r, s must be in [1, n-1]; reject zero and out-of-range (malleability /
        # invalid-signature hardening).
        if not (1 <= r < order and 1 <= s < order):
            return False
        if _strict_low_s and s > order // 2:
            return False
        pub = _coerce_pubkey(public_key, curve)
        der = encode_dss_signature(r, s)
        try:
            pub.verify(der, signing_base.encode("utf-8"), ec.ECDSA(hash_alg))
        except InvalidSignature:
            return False
        return True

    return _verify


verify_p256 = _make_verifier(ec.SECP256R1(), hashes.SHA256(), 32, _N_P256)
verify_p384 = _make_verifier(ec.SECP384R1(), hashes.SHA384(), 48, _N_P384)


__all__ = [
    "ECDSAError",
    "set_strict_low_s",
    "verify_p256",
    "verify_p384",
]
