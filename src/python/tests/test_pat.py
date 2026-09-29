import struct
import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from cryptography.hazmat.primitives import hashes

from pat import PatUtils, PatValidator, PrivateAccessToken
from engine import FingerprintEngine, RequestContext, InMemoryStore


def create_test_token(token_type: int, private_key, custom_key_id: bytes = None) -> bytes:
    nonce = b"\x01" * 32
    challenge_digest = b"\x02" * 32
    token_key_id = custom_key_id if custom_key_id is not None else b"\x03" * 32

    signed_data = struct.pack("!H", token_type) + nonce + challenge_digest + token_key_id

    if token_type in (1, 2):
        sig = private_key.sign(
            signed_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    elif token_type == 3:
        sig = private_key.sign(signed_data)
    else:
        sig = b"\x00" * 64

    return signed_data + sig


@pytest.mark.asyncio
async def test_pat_header_extraction_and_parsing():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw_token = create_test_token(1, private_key)
    b64 = base64.b64encode(raw_token).decode("utf-8")

    headers_auth = {"Authorization": f'PrivateToken token="{b64}"'}
    tokens = PatUtils.extract_tokens(headers_auth)
    assert len(tokens) == 1
    assert tokens[0] == raw_token

    parsed = PatUtils.parse_token(tokens[0])
    assert parsed is not None
    assert parsed.token_type == 1
    assert len(parsed.nonce) == 32


@pytest.mark.asyncio
async def test_pat_verification_and_anti_replay():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = b"\x42" * 32
    raw_token = create_test_token(1, private_key, custom_key_id=key_id)
    b64 = base64.b64encode(raw_token).decode("utf-8")

    store = InMemoryStore()
    validator = PatValidator(
        trusted_keys={key_id.hex(): private_key.public_key()},
        nonce_store=store,
    )

    headers = {"Authorization": f'PrivateToken token="{b64}"'}

    # Premier passage : validation OK
    res1 = await validator.process_request_headers(headers)
    assert res1.is_verified is True
    assert res1.vector.get("pat_verified") == 100.0

    # Deuxième passage (rejeu) : rejeté
    res2 = await validator.process_request_headers(headers)
    assert res2.is_verified is False


@pytest.mark.asyncio
async def test_pat_does_not_protect_condemned_device():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = b"\x55" * 32
    raw_token = create_test_token(1, private_key, custom_key_id=key_id)
    b64 = base64.b64encode(raw_token).decode("utf-8")

    store = InMemoryStore()
    validator = PatValidator(trusted_keys={key_id.hex(): private_key.public_key()}, nonce_store=store)
    engine = FingerprintEngine({"patValidator": validator}, store)

    device_id = "condemned-python-dev"
    await store.set(f"device:{device_id}", {"condemned": True, "initialDeviceHash": "abc"})

    context = RequestContext(
        client_ip="1.2.3.4",
        path="/",
        headers={"Authorization": f'PrivateToken token="{b64}"', "user-agent": "Mozilla/5.0"},
        cookies={"device_id": device_id}
    )

    decision = await engine.process_request(context)
    assert decision["action"] == "block"
    assert decision.get("status") == 403


@pytest.mark.asyncio
async def test_pat_does_not_protect_certain_attack():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = b"\x66" * 32
    raw_token = create_test_token(1, private_key, custom_key_id=key_id)
    b64 = base64.b64encode(raw_token).decode("utf-8")

    store = InMemoryStore()
    validator = PatValidator(trusted_keys={key_id.hex(): private_key.public_key()}, nonce_store=store)
    config = {
        "patValidator": validator,
        "honeypot": {"trapUrls": ["/.env"]}
    }
    engine = FingerprintEngine(config, store)

    context = RequestContext(
        client_ip="1.2.3.4",
        path="/.env",  # Honeypot déclenché
        headers={"Authorization": f'PrivateToken token="{b64}"', "user-agent": "Mozilla/5.0"},
        cookies={}
    )

    decision = await engine.process_request(context)
    assert decision["action"] == "block"
    assert decision.get("status") == 403


@pytest.mark.asyncio
async def test_pat_valid_exempts_from_pow_computation():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_id = b"\x77" * 32
    raw_token = create_test_token(1, private_key, custom_key_id=key_id)
    b64 = base64.b64encode(raw_token).decode("utf-8")

    store = InMemoryStore()
    validator = PatValidator(trusted_keys={key_id.hex(): private_key.public_key()}, nonce_store=store)
    config = {
        "patValidator": validator,
        "thresholds": {"low": 10, "medium": 40, "high": 70, "block": 95},
        "weights": {"headerAnomalyScore": 1.0}
    }
    engine = FingerprintEngine(config, store)

    # Requête suspecte qui déclencherait normalement un challenge PoW
    context = RequestContext(
        client_ip="1.2.3.4",
        path="/",
        headers={
            "Authorization": f'PrivateToken token="{b64}"',
            "user-agent": "curl/7.0"
        },
        cookies={}
    )

    decision = await engine.process_request(context)

    # Dispense immédiate du calcul PoW
    assert decision["action"] == "next"
    assert decision["score"] == 0.0
    assert decision["vector"].get("pat_verified") == 100.0