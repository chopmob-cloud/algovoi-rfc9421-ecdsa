"""algovoi-rfc9421-ecdsa — ECDSA (P-256/P-384) add-on for the AlgoVoi RFC 9421 verifier.

A PURE add-on: it does not modify or re-publish the core verifier. It provides a
drop-in `verify_request` that accepts Ed25519 (delegated verbatim to the untouched
`algovoi-rfc9421-verifier`) plus the RFC 9421 ECDSA suites `ecdsa-p256-sha256` and
`ecdsa-p384-sha384`, reusing the verifier's hardened primitives and adding only the
ECDSA signature check.

    from algovoi_rfc9421_ecdsa import verify_request
    result = verify_request(
        method="POST", authority="api.example.com", path="/a2a",
        headers=headers, body=body, public_key=sec1_point_bytes,
        allowed_algorithms={"ecdsa-p256-sha256"},
    )

The core verifier stays Ed25519 + PyNaCl-only and unchanged; this package brings
its own `cryptography` dependency. Apache-2.0.
"""
from algovoi_rfc9421_ecdsa.request import DEFAULT_ALLOWED, verify_request
from algovoi_rfc9421_ecdsa.verify import (
    ECDSAError,
    set_strict_low_s,
    verify_p256,
    verify_p384,
)

__version__ = "0.1.0"

__all__ = [
    "verify_request",
    "DEFAULT_ALLOWED",
    "ECDSAError",
    "set_strict_low_s",
    "verify_p256",
    "verify_p384",
]
