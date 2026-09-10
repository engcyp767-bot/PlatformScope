"""
Platform Scope - Cryptographic Engine
Implements Ed25519 (RFC 8032) digital signature generation and verification
in pure Python using only standard library (hashlib, os). Zero external pip dependencies.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

# ==============================================================================
# RFC 8032 Ed25519 Pure Python Implementation
# ==============================================================================

b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493


def _inv(z: int, m: int = q) -> int:
    return pow(z, m - 2, m)


d = (-121665 * _inv(121666)) % q
I = pow(2, (q - 1) // 4, q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = 4 * _inv(5) % q
Bx = _xrecover(By)
B = [Bx % q, By % q]


def _edwards_add(P: list[int], Q: list[int]) -> list[int]:
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    denom_x = (1 + d * x1 * x2 * y1 * y2) % q
    denom_y = (1 - d * x1 * x2 * y1 * y2) % q
    x3 = (x1 * y2 + x2 * y1) * _inv(denom_x) % q
    y3 = (y1 * y2 + x1 * x2) * _inv(denom_y) % q
    return [x3, y3]


def _scalarmult(P: list[int], e: int) -> list[int]:
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _encodeint(y: int) -> bytes:
    return y.to_bytes(32, "little")


def _decodeint(b_bytes: bytes) -> int:
    return int.from_bytes(b_bytes, "little")


def _encodepoint(P: list[int]) -> bytes:
    x, y = P[0], P[1]
    bits = [(y >> i) & 1 for i in range(b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(b // 8))


def _decodepoint(s: bytes) -> list[int]:
    y = sum(2**i * ((s[i // 8] >> (i % 8)) & 1) for i in range(b - 1))
    x = _xrecover(y)
    if x & 1 != ((s[b // 8 - 1] >> 7) & 1):
        x = q - x
    P = [x, y]
    # Verify point lies on curve
    if (-P[0] * P[0] + P[1] * P[1] - 1 - d * P[0] * P[0] * P[1] * P[1]) % q != 0:
        raise ValueError("Decoded point not on Curve25519")
    return P


def generate_keypair(sk_seed: bytes | None = None) -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair from an optional seed or random bytes."""
    if sk_seed is None:
        sk_seed = os.urandom(32)
    elif len(sk_seed) != 32:
        sk_seed = hashlib.sha256(sk_seed).digest()
    h = hashlib.sha512(sk_seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")
    A = _scalarmult(B, a)
    pk = _encodepoint(A)
    return sk_seed, pk


def sign(secret_key_seed: bytes, message: bytes) -> bytes:
    """Sign a message with Ed25519 private key seed (32 bytes). Returns 64-byte signature."""
    h = hashlib.sha512(secret_key_seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(a_bytes, "little")

    prefix = h[32:]
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % l
    R = _scalarmult(B, r)
    R_bytes = _encodepoint(R)

    A = _scalarmult(B, a)
    A_bytes = _encodepoint(A)

    k = int.from_bytes(hashlib.sha512(R_bytes + A_bytes + message).digest(), "little") % l
    S = (r + k * a) % l
    S_bytes = _encodeint(S)
    return R_bytes + S_bytes


def verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Verify Ed25519 signature (64 bytes) against public_key (32 bytes) and message."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        R_bytes = signature[:32]
        S_bytes = signature[32:]
        S = _decodeint(S_bytes)
        if S >= l:
            return False
        A = _decodepoint(public_key)
        R = _decodepoint(R_bytes)

        k = int.from_bytes(hashlib.sha512(R_bytes + public_key + message).digest(), "little") % l
        SB = _scalarmult(B, S)
        R_plus_kA = _edwards_add(R, _scalarmult(A, k))
        return SB == R_plus_kA
    except Exception:
        return False


# ==============================================================================
# Platform Scope Official Public Verification Key
# Hardcoded in the client application. The corresponding private signing key
# is held strictly offline by the License Issuer.
# ==============================================================================

PLATFORM_SCOPE_PUBLIC_KEY_HEX = (
    "9a4c568f6f32e18d6978435d18d451296ba1e46f6634568e2f8ebf9db1c54b32"
)


def get_public_key() -> bytes:
    return bytes.fromhex(PLATFORM_SCOPE_PUBLIC_KEY_HEX)


def serialize_payload(payload: dict[str, Any]) -> bytes:
    """Deterministic canonical JSON serialization for signing and verification."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def create_license_envelope(payload: dict[str, Any], private_key_seed: bytes) -> str:
    """Given a license payload dict and issuer private key seed, returns standard .lic envelope."""
    payload_bytes = serialize_payload(payload)
    sig_bytes = sign(private_key_seed, payload_bytes)
    envelope = {
        "format": "PLATFORM_SCOPE_LICENSE_V1",
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "signature": base64.b64encode(sig_bytes).decode("ascii"),
    }
    return json.dumps(envelope, indent=2)


def verify_license_envelope(envelope_text: str, public_key: bytes | None = None) -> tuple[bool, dict[str, Any] | None, str]:
    """
    Verifies a .lic envelope string against public_key.
    Returns: (is_valid, parsed_payload_dict, error_or_success_message)
    """
    if public_key is None:
        public_key = get_public_key()

    try:
        envelope = json.loads(envelope_text)
    except Exception:
        return False, None, "تنسيق ملف الترخيص غير صالح (JSON غير سليم)."

    if not isinstance(envelope, dict) or envelope.get("format") != "PLATFORM_SCOPE_LICENSE_V1":
        return False, None, "نوع ملف الترخيص غير معتمد (Format mismatch)."

    payload_b64 = envelope.get("payload", "")
    sig_b64 = envelope.get("signature", "")

    try:
        payload_bytes = base64.b64decode(payload_b64)
        sig_bytes = base64.b64decode(sig_b64)
    except Exception:
        return False, None, "تعذر فك ترميز بيانات الترخيص أو التوقيع الرقمي."

    if not verify(public_key, sig_bytes, payload_bytes):
        return False, None, "التوقيع الرقمي غير صالح أو تم التلاعب ببيانات ملف الترخيص."

    try:
        payload_dict = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return False, None, "محتوى بيانات الترخيص غير صالح بعد فك التشفير."

    return True, payload_dict, "تم التحقق من التوقيع الرقمي بنجاح."

