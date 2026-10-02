import re
import struct
import base64
import asyncio
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import padding, ed25519, rsa
from cryptography.hazmat.primitives import hashes

PRIVATE_TOKEN_PATTERN = re.compile(r'token=(?:"([^"]+)"|([a-zA-Z0-9_\-+/=]+))', re.IGNORECASE)


@dataclass
class PrivateAccessToken:
    token_type: int
    nonce: bytes
    challenge_digest: bytes
    token_key_id: bytes
    authenticator: bytes
    signed_data: bytes

    @property
    def nonce_hex(self) -> str:
        return self.nonce.hex()

    @property
    def token_key_id_hex(self) -> str:
        return self.token_key_id.hex()

    @property
    def challenge_digest_hex(self) -> str:
        return self.challenge_digest.hex()


class PatValidationResult:
    def __init__(self, action: str, score: float, vector: Dict[str, float], verified: bool):
        self.action = action
        self.score = score
        self.vector = vector or {}
        self.is_verified = verified

    @classmethod
    def create_bypass(cls) -> "PatValidationResult":
        return cls("next", 0.0, {"pat_verified": 100.0, "privacy_pass": 100.0}, True)

    @classmethod
    def not_applicable(cls) -> "PatValidationResult":
        return cls("next", 0.0, {}, False)


class PatUtils:
    @staticmethod
    def decode_base64_safe(input_str: Optional[str]) -> Optional[bytes]:
        if not input_str:
            return None
        normalized = input_str.strip().replace('-', '+').replace('_', '/')
        remainder = len(normalized) % 4
        if remainder > 0:
            normalized += '=' * (4 - remainder)
        try:
            return base64.b64decode(normalized)
        except Exception:
            return None

    @staticmethod
    def extract_tokens(headers: Optional[Dict[str, str]]) -> List[bytes]:
        tokens: List[bytes] = []
        if not headers:
            return tokens

        # Recherche dans Authorization: PrivateToken token="..."
        auth_header = None
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth_header = v
                break

        if auth_header and auth_header.strip().lower().startswith("privatetoken "):
            matcher = PRIVATE_TOKEN_PATTERN.search(auth_header)
            if matcher:
                raw_b64 = matcher.group(1) if matcher.group(1) is not None else matcher.group(2)
                decoded = PatUtils.decode_base64_safe(raw_b64)
                if decoded and len(decoded) >= 98:
                    tokens.append(decoded)

        # Recherche dans Sec-Private-State-Token
        pst_header = None
        for k, v in headers.items():
            if k.lower() == "sec-private-state-token":
                pst_header = v
                break

        if pst_header and pst_header.strip():
            parts = pst_header.split(",")
            for part in parts:
                trimmed = part.strip()
                if trimmed:
                    decoded = PatUtils.decode_base64_safe(trimmed)
                    if decoded and len(decoded) >= 98:
                        tokens.append(decoded)

        return tokens

    @staticmethod
    def parse_token(binary: Optional[bytes]) -> Optional[PrivateAccessToken]:
        if not binary or len(binary) < 98:
            return None

        token_type = struct.unpack("!H", binary[0:2])[0]
        nonce = binary[2:34]
        challenge_digest = binary[34:66]
        token_key_id = binary[66:98]
        authenticator = binary[98:]
        if not authenticator:
            return None

        signed_data = binary[0:98]
        return PrivateAccessToken(
            token_type=token_type,
            nonce=nonce,
            challenge_digest=challenge_digest,
            token_key_id=token_key_id,
            authenticator=authenticator,
            signed_data=signed_data,
        )

    @staticmethod
    def verify_signature(token: Optional[PrivateAccessToken], public_key: Any) -> bool:
        if token is None or public_key is None:
            return False

        token_type = token.token_type
        signed_data = token.signed_data
        authenticator = token.authenticator

        try:
            # Blind RSA-2048 (0x0001) / Rate-Limited Blind RSA (0x0002)
            if token_type in (1, 2, 0x0001, 0x0002):
                # 1. RSA-PSS SHA-384
                try:
                    public_key.verify(
                        authenticator,
                        signed_data,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48),
                        hashes.SHA384(),
                    )
                    return True
                except Exception:
                    pass

                # 2. RSA-PSS SHA-256
                try:
                    public_key.verify(
                        authenticator,
                        signed_data,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                        hashes.SHA256(),
                    )
                    return True
                except Exception:
                    pass

                # 3. Fallback PKCS#1 v1.5 SHA-256
                try:
                    public_key.verify(authenticator, signed_data, padding.PKCS1v15(), hashes.SHA256())
                    return True
                except Exception:
                    pass

            elif token_type in (3, 0x0003):
                # VOPRF / Ed25519
                try:
                    public_key.verify(authenticator, signed_data)
                    return True
                except Exception:
                    pass
        except Exception:
            return False

        return False


class PatValidator:
    def __init__(
        self,
        trusted_keys: Optional[Dict[str, Any]] = None,
        default_public_key: Optional[Any] = None,
        nonce_store: Optional[Any] = None,
        nonce_ttl_seconds: int = 86400,
    ):
        self.trusted_keys = trusted_keys or {}
        self.default_public_key = default_public_key
        self.nonce_store = nonce_store
        self.nonce_ttl_seconds = nonce_ttl_seconds if nonce_ttl_seconds > 0 else 86400

    def resolve_key(self, key_id_hex: Optional[str]) -> Optional[Any]:
        if not key_id_hex:
            return self.default_public_key
        key = self.trusted_keys.get(key_id_hex)
        if key is None:
            key = self.trusted_keys.get(key_id_hex.lower())
        return key if key is not None else self.default_public_key

    async def process_request_headers(self, headers: Dict[str, str]) -> PatValidationResult:
        raw_tokens = PatUtils.extract_tokens(headers)
        if not raw_tokens:
            return PatValidationResult.not_applicable()

        for raw_token in raw_tokens:
            parsed_token = PatUtils.parse_token(raw_token)
            if not parsed_token:
                continue

            nonce_hex = parsed_token.nonce_hex
            if self.nonce_store is not None:
                exists = self.nonce_store.has(f"pat-nonce:{nonce_hex}")
                if asyncio.iscoroutine(exists):
                    exists = await exists
                if exists:
                    continue

            key = self.resolve_key(parsed_token.token_key_id_hex)
            if key is None:
                continue

            is_valid = PatUtils.verify_signature(parsed_token, key)
            if is_valid:
                if self.nonce_store is not None:
                    nonce_key = f"pat-nonce:{nonce_hex}"
                    if hasattr(self.nonce_store, "set_nx"):
                        acquired = self.nonce_store.set_nx(nonce_key, True, self.nonce_ttl_seconds)
                        if asyncio.iscoroutine(acquired):
                            acquired = await acquired
                        if not acquired:
                            continue
                    else:
                        res = self.nonce_store.set(nonce_key, True, self.nonce_ttl_seconds)
                        if asyncio.iscoroutine(res):
                            await res
                return PatValidationResult.create_bypass()

        return PatValidationResult.not_applicable()