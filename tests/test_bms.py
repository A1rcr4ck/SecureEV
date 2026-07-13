import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

import time
from bus.virtual_bus import VirtualBus
from modules.kms import KMS
from modules.bms_ecu import BMSECU
from crypto.mac import verify_mac


def test_bms_transmit():
    master_key = b'secureev_master_key_32bytes!!!!!'
    bus = VirtualBus()
    kms = KMS(master_key)
    bms = BMSECU(kms, bus)

    frame = bms.transmit(
        voltage=400.5,
        temperature=35.0,
        soc=85
    )

    assert frame.can_id == 0x100
    assert frame.counter == 0
    assert len(frame.payload) == 4
    assert len(frame.mac) == 2
    assert len(bus.frames) == 1
    print("PASS: frame transmitted and stored on bus")


def test_mac_verification():
    master_key = b'secureev_master_key_32bytes!!!!!'
    bus = VirtualBus()
    kms = KMS(master_key)
    bms = BMSECU(kms, bus)

    frame = bms.transmit(400.5, 35.0, 85)
    session_key = KMS(master_key).get_session_key(0x100)

    result = verify_mac(
        session_key,
        frame.can_id,
        frame.counter,
        frame.payload,
        frame.mac
    )
    assert result, "MAC verification failed"
    print("PASS: MAC verified successfully")


def test_payload_encoding():
    master_key = b'secureev_master_key_32bytes!!!!!'
    bus = VirtualBus()
    kms = KMS(master_key)
    bms = BMSECU(kms, bus)

    frame = bms.transmit(400.5, 35.0, 85)
    decoded = bms.decode_payload(frame.payload)

    assert decoded["voltage"] == 400.5
    assert decoded["temperature"] == 35.0
    assert decoded["soc"] == 85
    print("PASS: payload encoded and decoded correctly")


def test_replay_counter():
    master_key = b'secureev_master_key_32bytes!!!!!'
    bus = VirtualBus()
    kms = KMS(master_key)
    bms = BMSECU(kms, bus)

    f1 = bms.transmit(400.5, 35.0, 85)
    f2 = bms.transmit(401.0, 36.0, 84)
    f3 = bms.transmit(401.5, 37.0, 83)

    assert f1.counter == 0
    assert f2.counter == 1
    assert f3.counter == 2
    print("PASS: monotonic counter increments correctly")


if __name__ == "__main__":
    print("Running BMS ECU tests...\n")
    test_bms_transmit()
    test_mac_verification()
    test_payload_encoding()
    test_replay_counter()
    print("\nAll tests passed.")