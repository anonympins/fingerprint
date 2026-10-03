import base64
import hashlib
import json
import struct
import time
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hardware_attestation import (
    AppleAppAttestValidator,
    PlayIntegrityValidator,
    DbscSessionManager,
    HardwareAttestationManager,
)
from engine import FingerprintEngine, RequestContext, InMemoryStore


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def create_ec_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def test_apple_app_attest_valid_assertion_increments_counter():
    priv_key, pub_key = create_ec_key_pair()
    stored_counter = 10
    new_counter = 11

    rp_id_hash = b"\xAA" * 32
    flags = b"\x01"
    counter_bytes = struct.pack("!I", new_counter)
    auth_data = rp_id_hash + flags + counter_bytes

    client_data_hash = hashlib.sha256(b"session_id:192.168.1.10").digest()
    signed_data = auth_data + client_data_hash
    signature = priv_key.sign(signed_data, ec.ECDSA(hashes.SHA256()))
    assertion_raw = auth_data + signature

    is_valid, returned_counter = AppleAppAttestValidator.verify_assertion(
        public_key=pub_key,
        assertion_raw=assertion_raw,
        client_data_hash=client_data_hash,
        stored_counter=stored_counter,
    )

    assert is_valid is True
    assert returned_counter == new_counter


def test_apple_app_attest_rejects_replayed_counter():
    priv_key, pub_key = create_ec_key_pair()
    stored_counter = 15
    stale_counter = 15

    auth_data = b"\xAA" * 32 + b"\x01" + struct.pack("!I", stale_counter)
    client_data_hash = hashlib.sha256(b"session_id:127.0.0.1").digest()
    signature = priv_key.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
    assertion_raw = auth_data + signature

    is_valid, returned_counter = AppleAppAttestValidator.verify_assertion(
        public_key=pub_key,
        assertion_raw=assertion_raw,
        client_data_hash=client_data_hash,
        stored_counter=stored_counter,
    )

    assert is_valid is False
    assert returned_counter == stored_counter


def test_google_play_integrity_valid_token():
    expected_nonce = "anti-replay-nonce-xyz"
    pkg_name = "com.anonympins.app"

    header = {"alg": "ES256"}
    payload = {
        "requestDetails": {
            "nonce": expected_nonce,
            "timestampMillis": str(int(time.time() * 1000)),
        },
        "appIntegrity": {"packageName": pkg_name},
        "deviceIntegrity": {
            "deviceRecognitionVerdict": ["MEETS_STRONG_INTEGRITY", "MEETS_DEVICE_INTEGRITY"]
        },
    }

    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    sig_b64 = base64url_encode(b"mock_valid_signature")
    jws_token = f"{header_b64}.{payload_b64}.{sig_b64}"

    is_valid, claims = PlayIntegrityValidator.decode_and_verify_jws(
        token=jws_token,
        expected_package_name=pkg_name,
        expected_nonce=expected_nonce,
    )

    assert is_valid is True
    assert claims["appIntegrity"]["packageName"] == pkg_name


def test_google_play_integrity_rejects_package_or_nonce_mismatch():
    header_b64 = base64url_encode(b'{"alg":"ES256"}')
    payload = {
        "requestDetails": {
            "nonce": "expected-nonce",
            "timestampMillis": str(int(time.time() * 1000)),
        },
        "appIntegrity": {"packageName": "com.fraudulent.repack"},
        "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_STRONG_INTEGRITY"]},
    }
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    jws = f"{header_b64}.{payload_b64}.fakesig"

    is_valid_pkg, _ = PlayIntegrityValidator.decode_and_verify_jws(
        jws, expected_package_name="com.anonympins.app", expected_nonce="expected-nonce"
    )
    assert is_valid_pkg is False

    is_valid_nonce, _ = PlayIntegrityValidator.decode_and_verify_jws(
        jws, expected_package_name="com.fraudulent.repack", expected_nonce="wrong-nonce"
    )
    assert is_valid_nonce is False


def test_dbsc_session_proof_verification_success():
    priv_key, pub_key = create_ec_key_pair()
    pub_numbers = pub_key.public_numbers()

    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(pub_numbers.x.to_bytes(32, "big")),
        "y": base64url_encode(pub_numbers.y.to_bytes(32, "big")),
    }

    session_id = "device_session_456"
    origin = "https://example.com"
    nonce = "dbsc_challenge_nonce_789"

    header = {"typ": "dbsc+jwt", "alg": "ES256"}
    payload = {
        "sub": session_id,
        "aud": origin,
        "nonce": nonce,
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }

    header_b64 = base64url_encode(json.dumps(header).encode("utf-8"))
    payload_b64 = base64url_encode(json.dumps(payload).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"

    der_sig = priv_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    raw_ieee_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    dbsc_jwt = f"{signing_input}.{base64url_encode(raw_ieee_sig)}"

    is_valid = DbscSessionManager.verify_session_proof(
        dbsc_jwt=dbsc_jwt,
        public_key_jwk=jwk,
        expected_session_id=session_id,
        expected_origin=origin,
        expected_nonce=nonce,
    )

    assert is_valid is True


@pytest.mark.asyncio
async def test_hardware_attestation_manager_dbsc_bypass():
    store = InMemoryStore()
    manager = HardwareAttestationManager(store)

    priv_key, pub_key = create_ec_key_pair()
    pub_numbers = pub_key.public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(pub_numbers.x.to_bytes(32, "big")),
        "y": base64url_encode(pub_numbers.y.to_bytes(32, "big")),
    }

    session_id = "sess_active_1"
    origin = "https://app.example.com"
    nonce = "nonce_tpm_xyz"

    await store.set(f"dbsc-session:{session_id}", {"jwk": jwk})
    await store.set(f"dbsc-nonce:{session_id}", nonce)

    header = {"typ": "dbsc+jwt", "alg": "ES256"}
    payload = {"sub": session_id, "aud": origin, "nonce": nonce, "exp": int(time.time()) + 300}
    signing_input = f"{base64url_encode(json.dumps(header).encode())}.{base64url_encode(json.dumps(payload).encode())}"
    der_sig = priv_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    dbsc_jwt = f"{signing_input}.{base64url_encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    headers = {"sec-session-response": dbsc_jwt}
    res = await manager.process_hardware_attestation(
        headers=headers,
        session_id=session_id,
        client_ip="1.2.3.4",
        origin=origin,
    )

    assert res.is_verified is True
    assert res.attestation_type == "dbsc_tpm"
    assert await store.get(f"dbsc-nonce:{session_id}") is None


@pytest.mark.asyncio
async def test_hardware_attestation_unverified_when_empty():
    store = InMemoryStore()
    manager = HardwareAttestationManager(store)

    res = await manager.process_hardware_attestation(
        headers={"user-agent": "Browser/1.0"},
        session_id="none",
        client_ip="127.0.0.1",
        origin="https://example.com",
    )
    assert res.is_verified is False
    assert res.attestation_type == "none"