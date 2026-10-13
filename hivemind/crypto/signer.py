"""The signer seam: the one place a private key is turned into a signature (3.1, phase 2).

Every signing call in core (journal entries, owner governance, Hive-Auth request envelopes, hello proofs)
asks a `Signer` for `sign(message)` and `public_key()`. No caller holds a raw seed to sign with, because a
backend whose key lives elsewhere (a hardware key, a TPM, a gateway) cannot hand one over. Today there is one
backend, `FileSigner`: the 32-byte seed already read from the key file, signed with the bundled `ed25519`.
Same bytes in, same signature out: the seam changes who holds the seed, not what is signed.

Signing only. Verification stays fixed in core (`ed25519.verify`), so a backend can fail to sign but cannot
make a forgery verify. Capsule decryption needs X25519 secret material, which a sign-only backend cannot
supply, so it does not go through here. Module signing (`hive_module_client.py`) uses the module's own key and
is out of scope.

This module imports nothing local but `ed25519`, so `hv` can use it without reaching the owner-key code (2.0 S2):
the owner seed is read and the owner signer is built only on the control plane (`hivemind_owner.py`).
tests/test_signer_seam.py fails on a call to `ed25519.sign` anywhere else.
"""

try:
    import ed25519 as _ed25519      # bundled pure-Python signer
except Exception:                   # a build without the bundled crypto: no signer
    _ed25519 = None


class Signer:
    """What a backend provides. `sign` returns the 64-byte Ed25519 signature of `message`; `public_key` the
    32-byte key that verifies it."""

    __slots__ = ()

    def public_key(self):
        raise NotImplementedError

    def sign(self, message):
        raise NotImplementedError


class FileSigner(Signer):
    """The key-file backend: signs with a seed the caller already loaded from its key file."""

    __slots__ = ("_seed", "_pub")

    def __init__(self, seed):
        if _ed25519 is None:
            raise RuntimeError("no bundled ed25519: cannot sign")
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        self._seed = bytes(seed)
        self._pub = _ed25519.pub_from_seed(self._seed)

    def public_key(self):
        return self._pub

    def sign(self, message):
        return _ed25519.sign(message, self._seed)

    def __repr__(self):
        return "<FileSigner>"           # never the seed


def from_seed(seed):
    """A `FileSigner` for `seed`, or None when there is nothing to sign with (no seed, or no bundled crypto)."""
    if seed is None or _ed25519 is None:
        return None
    return FileSigner(seed)
