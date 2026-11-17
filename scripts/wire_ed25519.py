"""Ed25519 of RFC 8032, for scripts/check-wire-vectors.py (T-723).

The standard library has no Ed25519, and the check must share no code
with podssh's codecs, so the curve is written here from the RFC: the public
key of a seed, a signature, and its verification. Slow, and for test
vectors alone: no secret of a user ever passes through it.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _inv(x: int) -> int:
    return pow(x, P - 2, P)


def _x_of(y: int, sign: int) -> int | None:
    """The x of a point from its y and the sign bit; None off the curve."""
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P != 0:
        return None
    if x == 0 and sign:
        return None
    if x % 2 != sign:
        x = P - x
    return x


_BY = 4 * _inv(5) % P
_BX = _x_of(_BY, 0)
BASE = (_BX, _BY, 1, _BX * _BY % P)
IDENTITY = (0, 1, 1, 0)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    pa = (y1 - x1) * (y2 - x2) % P
    pb = (y1 + x1) * (y2 + x2) % P
    pc = t1 * 2 * D * t2 % P
    pd = z1 * 2 * z2 % P
    e, f, g, h = pb - pa, pd - pc, pd + pc, pb + pa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, point):
    out = IDENTITY
    while s > 0:
        if s & 1:
            out = _add(out, point)
        point = _add(point, point)
        s >>= 1
    return out


def _encode(point) -> bytes:
    x, y, z, _ = point
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(raw: bytes):
    if len(raw) != 32:
        return None
    y = int.from_bytes(raw, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    x = _x_of(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _same(a, b) -> bool:
    return (a[0] * b[2] - b[0] * a[2]) % P == 0 and (a[1] * b[2] - b[1] * a[2]) % P == 0


def _expand(seed: bytes) -> tuple[int, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public(seed: bytes) -> bytes:
    """The public key of a 32-byte seed."""
    return _encode(_mul(_expand(seed)[0], BASE))


def sign(seed: bytes, message: bytes) -> bytes:
    """The deterministic signature of RFC 8032, 64 bytes."""
    scalar, prefix = _expand(seed)
    key = _encode(_mul(scalar, BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    big_r = _encode(_mul(r, BASE))
    k = int.from_bytes(hashlib.sha512(big_r + key + message).digest(), "little") % L
    return big_r + ((r + k * scalar) % L).to_bytes(32, "little")


def verify(key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether `signature` is `key`'s of `message`; S must be under L."""
    if len(signature) != 64:
        return False
    a, big_r = _decode(key), _decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or big_r is None or s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + key + message).digest(), "little") % L
    return _same(_mul(s, BASE), _add(big_r, _mul(k, a)))


def self_test() -> list[str]:
    """RFC 8032, section 7.1, test 1: a wrong curve fails here first."""
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    problems = []
    if public(seed) != key:
        problems.append("Ed25519: the public key of RFC 8032's test 1 is wrong")
    if sign(seed, b"") != sig:
        problems.append("Ed25519: the signature of RFC 8032's test 1 is wrong")
    if not verify(key, b"", sig) or verify(key, b"x", sig):
        problems.append("Ed25519: the verification of RFC 8032's test 1 is wrong")
    return problems
