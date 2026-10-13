"""CK-7: a small-order public key verified signatures nobody made, so an entry or governance act could be
forged with no secret at all. The verifier refuses such keys and `_canon_pub` will not admit one."""
import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_genesis_pin import hv, HIVE_ID, T_GENESIS  # noqa: E402,F401  (the `hv` fixture)

IDENTITY = (1).to_bytes(32, "little")               # the neutral point: y = 1
FORGED = IDENTITY + bytes(32)                       # R = identity, S = 0: verifies under the identity key for ANY message


def b64(b):
    return base64.b64encode(b).decode()


def test_identity_key_signature_verifies_nothing(hv):
    assert not hv._ed25519.verify(b"any message at all", FORGED, IDENTITY)
    assert not hv._ed25519.verify(b"another", FORGED, IDENTITY)


def test_forged_device_entry_is_rejected(hv):
    entry = {"node_id": hv._device_id_for_pub(IDENTITY), "seq": 1, "type": "fact", "timestamp": T_GENESIS,
             "payload": {"content": "forged", "tags": [], "source": "manual"},
             "pub": b64(IDENTITY), "sig": b64(FORGED)}
    assert hv._verify_entry(entry) is False


def test_forged_governance_act_is_rejected(hv):
    payload = {"action": "owner", "owner_id": hv._owner_id_for_pub(IDENTITY), "owner_pub": b64(IDENTITY),
               "hive_id": HIVE_ID, "owner_sig": b64(FORGED)}
    assert hv._verify_governance(payload) is None


def test_small_order_owner_key_is_not_canonical(hv):
    assert hv._canon_pub(b64(IDENTITY)) is None
    order2 = (2 ** 255 - 20).to_bytes(32, "little")           # y = q - 1, order 2
    assert hv._canon_pub(b64(order2)) is None
    good = hv._ed25519.pub_from_seed(b"\x07" * 32)
    assert hv._canon_pub(b64(good)) == b64(good)
