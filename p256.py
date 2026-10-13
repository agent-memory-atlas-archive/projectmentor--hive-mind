"""ECDSA over NIST P-256 with SHA-256: VERIFY ONLY (WebAuthn alg -7, "ES256"). Owner approval slice A1.

There is no signing here and no key generation: the agent only checks a passkey assertion a phone made. Pure Python
integers, no dependency. Not constant time, which is fine for a verifier of public values. A public key is a point
(x, y) that must lie on the curve; a signature is (r, s) with 0 < r, s < n. Tests pin it to RFC 6979 A.2.5 and to
signatures made by OpenSSL.
"""

import hashlib

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def on_curve(pt):
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def _add(p1, p2):
    """Affine point addition; None is the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = _add(out, pt)
        pt = _add(pt, pt)
        k >>= 1
    return out


def verify(pub64, message, r, s):
    """True when (r, s) is a valid ECDSA-SHA256 signature of `message` under the 64-byte raw key `x || y`."""
    if not isinstance(pub64, (bytes, bytearray)) or len(pub64) != 64:
        return False
    q = (int.from_bytes(pub64[:32], "big"), int.from_bytes(pub64[32:], "big"))
    if not on_curve(q) or not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, N)
    pt = _add(_mul(e * w % N, G), _mul(r * w % N, q))
    return pt is not None and pt[0] % N == r


def parse_der(sig):
    """(r, s) from a DER ECDSA signature (SEQUENCE of two INTEGERs, as WebAuthn carries it), or None if it is not
    exactly that."""
    try:
        if len(sig) < 8 or sig[0] != 0x30 or sig[1] >= 0x80 or sig[1] != len(sig) - 2:
            return None
        i, ints = 2, []
        for _ in range(2):
            if sig[i] != 0x02:
                return None
            n = sig[i + 1]
            if n == 0 or n >= 0x80:
                return None
            v = sig[i + 2:i + 2 + n]
            if len(v) != n or v[0] & 0x80 or (n > 1 and v[0] == 0 and not v[1] & 0x80):
                return None
            ints.append(int.from_bytes(v, "big"))
            i += 2 + n
        return (ints[0], ints[1]) if i == len(sig) else None
    except IndexError:
        return None
