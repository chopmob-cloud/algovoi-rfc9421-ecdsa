"""Tests for the ECDSA pure-wrapper add-on (no core verifier changes)."""
import base64

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from algovoi_rfc9421_ecdsa import (
    ECDSAError,
    set_strict_low_s,
    verify_p256,
    verify_request,
)
from algovoi_rfc9421_verifier import (
    build_signing_base,
    compute_content_digest,
    parse_signature_input,
)

BASE = '"@method": POST\n"@path": /a2a\n"@signature-params": ("@method" "@path")'
N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _key():
    sk = ec.generate_private_key(ec.SECP256R1())
    pub = sk.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return sk, pub


def _raw(sk, base=BASE, low_s=True):
    r, s = decode_dss_signature(sk.sign(base.encode(), ec.ECDSA(hashes.SHA256())))
    if low_s and s > N_P256 // 2:
        s = N_P256 - s
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


# --- provider-level (raw signature) tests ---

def test_valid_signature_accepts():
    sk, pub = _key()
    assert verify_p256(BASE, _raw(sk), pub) is True


def test_tampered_base_rejected():
    sk, pub = _key()
    assert verify_p256(BASE + "x", _raw(sk), pub) is False


def test_flipped_signature_rejected():
    sk, pub = _key()
    sig = bytearray(_raw(sk)); sig[0] ^= 0x01
    assert verify_p256(BASE, bytes(sig), pub) is False


def test_wrong_length_raises():
    _, pub = _key()
    with pytest.raises(ECDSAError):
        verify_p256(BASE, b"\x00" * 63, pub)


def test_zero_rs_rejected():
    _, pub = _key()
    assert verify_p256(BASE, b"\x00" * 64, pub) is False


def test_invalid_point_raises():
    sk, _ = _key()
    with pytest.raises(ECDSAError):
        verify_p256(BASE, _raw(sk), b"\x04" + b"\x00" * 64)


def test_strict_low_s():
    sk, pub = _key()
    r, s = decode_dss_signature(sk.sign(BASE.encode(), ec.ECDSA(hashes.SHA256())))
    if s <= N_P256 // 2:
        s = N_P256 - s  # force high-s
    high = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert verify_p256(BASE, high, pub) is True
    set_strict_low_s(True)
    try:
        assert verify_p256(BASE, high, pub) is False
    finally:
        set_strict_low_s(False)


# --- end-to-end verify_request (wrapper, ECDSA path) ---

def _signed_ecdsa_request(sk, body=b'{"x":1}', created=1750000000, keyid="k"):
    cd = compute_content_digest(body)
    params = (
        f'("@method" "@path" "content-digest");created={created}'
        f';keyid="{keyid}";alg="ecdsa-p256-sha256"'
    )
    si = f"sig={params}"
    parsed = parse_signature_input(si)
    base = build_signing_base(
        parsed.covered_components, method="POST", authority="api.x", path="/a2a",
        scheme="https", headers={"content-digest": cd}, parameters=parsed.parameters,
        mode="rfc9421", signature_params_raw=parsed.params_block,
    )
    raw = _raw(sk, base=base)
    sig_hdr = "sig=:" + base64.b64encode(raw).decode() + ":"
    return {"signature-input": si, "signature": sig_hdr, "content-digest": cd}


def test_verify_request_ecdsa_end_to_end():
    sk, pub = _key()
    headers = _signed_ecdsa_request(sk)
    r = verify_request(
        method="POST", authority="api.x", path="/a2a",
        headers=headers, body=b'{"x":1}', public_key=pub,
        allowed_algorithms={"ecdsa-p256-sha256"},
    )
    assert r.valid is True
    assert r.signature_valid is True


def test_verify_request_ecdsa_not_allowed_rejected():
    sk, pub = _key()
    headers = _signed_ecdsa_request(sk)
    r = verify_request(
        method="POST", authority="api.x", path="/a2a",
        headers=headers, body=b'{"x":1}', public_key=pub,
        allowed_algorithms={"ed25519"},  # ECDSA not permitted
    )
    assert r.valid is False
    assert any("not in the allowed set" in e for e in r.errors)


def test_verify_request_tampered_body_rejected():
    sk, pub = _key()
    headers = _signed_ecdsa_request(sk)
    r = verify_request(
        method="POST", authority="api.x", path="/a2a",
        headers=headers, body=b'{"x":2}', public_key=pub,
        allowed_algorithms={"ecdsa-p256-sha256"},
    )
    assert r.valid is False
