# algovoi-rfc9421-ecdsa

[![PyPI](https://img.shields.io/pypi/v/algovoi-rfc9421-ecdsa)](https://pypi.org/project/algovoi-rfc9421-ecdsa/) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![npm](https://img.shields.io/npm/v/@algovoi/rfc9421-ecdsa)](https://www.npmjs.com/package/@algovoi/rfc9421-ecdsa)

ECDSA (P-256 / P-384) add-on for the
[AlgoVoi RFC 9421 verifier](https://pypi.org/project/algovoi-rfc9421-verifier/).

A **pure add-on**: it does not modify or re-publish the core verifier. It gives
you a drop-in `verify_request` that accepts Ed25519 (delegated verbatim to the
untouched verifier) plus the two RFC 9421-registered ECDSA suites:

- `ecdsa-p256-sha256` (RFC 9421 3.3.5): P-256, SHA-256, 64-byte `r‖s` signature
- `ecdsa-p384-sha384` (RFC 9421 3.3.6): P-384, SHA-384, 96-byte `r‖s` signature

The ECDSA path reuses the verifier's already-hardened primitives (Signature-Input
parsing, freshness/replay, Content-Digest, signing-base, downgrade/allow-list) and
adds only the ECDSA signature check. The core verifier stays Ed25519 + PyNaCl-only
and unchanged; this package brings its own `cryptography` dependency.

```python
from algovoi_rfc9421_ecdsa import verify_request

result = verify_request(
    method="POST", authority="api.example.com", path="/a2a",
    headers=headers, body=body, public_key=sec1_point_bytes,
    allowed_algorithms={"ecdsa-p256-sha256"},   # opt in per request
)
# Ed25519 requests are delegated to the core verifier automatically.
```

## Hardening

Before accepting an ECDSA signature the provider enforces:

- the public-key point is on the curve and not the identity;
- the signature is exactly the curve size (64 / 96 bytes, raw `r‖s`, not DER);
- `r` and `s` are each in `[1, n-1]`;
- optional canonical **low-`s`** enforcement (anti-malleability) via
  `set_strict_low_s(True)`, off by default for spec interop.

Apache-2.0.
