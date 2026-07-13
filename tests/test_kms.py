import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

from modules.kms import KMS
from bus.virtual_bus import VirtualBus
from modules.bms_ecu import BMSECU
from modules.gateway_ecu import GatewayECU


MASTER_KEY = b'secureev_master_key_32bytes!!!!!'


def test_kms_key_derivation():
    kms = KMS(MASTER_KEY)

    key_bms   = kms.get_session_key(0x100)
    key_motor = kms.get_session_key(0x200)
    key_obc   = kms.get_session_key(0x300)

    # Keys must be 32 bytes
    assert len(key_bms)   == 32
    assert len(key_motor) == 32
    assert len(key_obc)   == 32

    # Keys must be unique per CAN ID
    assert key_bms   != key_motor
    assert key_motor != key_obc
    assert key_bms   != key_obc

    print("PASS: unique 32-byte keys derived per CAN ID")


def test_kms_deterministic():
    kms1 = KMS(MASTER_KEY)
    kms2 = KMS(MASTER_KEY)

    # Same master key + same epoch = same session key
    assert kms1.get_session_key(0x100) == \
           kms2.get_session_key(0x100)
    print("PASS: key derivation is deterministic")


def test_kms_epoch_changes_keys():
    kms = KMS(MASTER_KEY)

    key_before = kms.get_session_key(0x100)
    kms.rotate()
    key_after = kms.get_session_key(0x100)

    assert key_before != key_after
    assert kms.get_epoch() == 1
    print("PASS: key changes after epoch rotation")


def test_kms_rotation_interval():
    kms = KMS(MASTER_KEY, rotation_interval=5)

    rotated = False
    for i in range(5):
        result = kms.tick()
        if result:
            rotated = True

    assert rotated is True
    assert kms.get_epoch() == 1
    assert len(kms.get_rotation_log()) == 1
    print("PASS: key rotation triggered at interval")


def test_kms_atomic_rotation_no_frame_loss():
    bus = VirtualBus()
    # Single shared KMS instance — both BMS and Gateway
    # use the same key material at all times
    kms = KMS(MASTER_KEY, rotation_interval=3)
    bms = BMSECU(kms, bus)
    gw  = GatewayECU(kms)

    accepted = 0
    rejected = 0
    for i in range(6):
        frame = bms.transmit(400.0 + i, 35.0, 85)
        if gw.receive(frame):
            accepted += 1
        else:
            rejected += 1

    assert accepted == 6, \
        f"Expected 6 accepted, got {accepted} " \
        f"({rejected} rejected)"
    assert kms.get_epoch() >= 1
    print(f"PASS: {accepted}/6 frames accepted across "
          f"{kms.get_epoch()} rotation(s) — zero frame loss")


def test_kms_master_key_validation():
    try:
        kms = KMS(b'short_key')
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"PASS: short master key rejected — {e}")


def test_kms_stats():
    kms = KMS(MASTER_KEY, rotation_interval=3)
    for _ in range(6):
        kms.tick()

    stats = kms.stats()
    assert stats["epoch"]     == 2
    assert stats["rotations"] == 2
    assert 0x100 in stats["known_ids"]
    print(f"PASS: KMS stats correct — "
          f"epoch={stats['epoch']} "
          f"rotations={stats['rotations']}")


if __name__ == "__main__":
    print("Running KMS tests...\n")
    test_kms_key_derivation()
    test_kms_deterministic()
    test_kms_epoch_changes_keys()
    test_kms_rotation_interval()
    test_kms_atomic_rotation_no_frame_loss()
    test_kms_master_key_validation()
    test_kms_stats()
    print("\nAll tests passed.")