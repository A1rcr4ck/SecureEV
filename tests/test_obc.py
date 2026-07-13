import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

from bus.virtual_bus import VirtualBus
from modules.kms import KMS
from modules.obc_ecu import OBCECU
from crypto.mac import verify_mac


MASTER_KEY = b'secureev_master_key_32bytes!!!!!'


def test_obc_transmit():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    obc = OBCECU(kms, bus, charger_allowlist=[0x01, 0x02])

    frame = obc.transmit(
        current_ma=16000,
        state=0x01,
        charger_id=0x01
    )

    assert frame is not None
    assert frame.can_id == 0x300
    assert frame.counter == 0
    assert len(frame.payload) == 4
    assert len(frame.mac) == 2
    assert len(bus.frames) == 1
    print("PASS: OBC frame transmitted and stored")


def test_obc_mac():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    obc = OBCECU(kms, bus, charger_allowlist=[0x01, 0x02])

    frame = obc.transmit(16000, 0x01, 0x01)
    session_key = KMS(MASTER_KEY).get_session_key(0x300)

    result = verify_mac(
        session_key,
        frame.can_id,
        frame.counter,
        frame.payload,
        frame.mac
    )
    assert result, "OBC MAC verification failed"
    print("PASS: OBC MAC verified")


def test_obc_payload_encoding():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    obc = OBCECU(kms, bus, charger_allowlist=[0x01])

    frame = obc.transmit(16000, 0x01, 0x01)
    decoded = obc.decode_payload(frame.payload)

    assert decoded["current_ma"] == 16000
    assert decoded["state"] == "Charging"
    assert decoded["charger_id"] == 0x01
    print("PASS: OBC payload encoded and decoded")


def test_rogue_charger_blocked():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    obc = OBCECU(kms, bus, charger_allowlist=[0x01, 0x02])

    # 0xAA is not in the allowlist
    frame = obc.transmit(16000, 0x01, 0xAA)

    assert frame is None
    assert len(bus.frames) == 0
    print("PASS: rogue charger ID blocked correctly")


def test_no_charger_allowed():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    obc = OBCECU(kms, bus, charger_allowlist=[0x01])

    # charger_id=0x00 means no charger connected
    frame = obc.transmit(0, 0x00, 0x00)

    assert frame is not None
    print("PASS: no-charger state (0x00) always allowed")


def test_obc_counter():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    obc = OBCECU(kms, bus, charger_allowlist=[0x01])

    f1 = obc.transmit(16000, 0x01, 0x01)
    f2 = obc.transmit(15000, 0x01, 0x01)
    f3 = obc.transmit(14000, 0x01, 0x01)

    assert f1.counter == 0
    assert f2.counter == 1
    assert f3.counter == 2
    print("PASS: OBC counter increments correctly")


if __name__ == "__main__":
    print("Running OBC ECU tests...\n")
    test_obc_transmit()
    test_obc_mac()
    test_obc_payload_encoding()
    test_rogue_charger_blocked()
    test_no_charger_allowed()
    test_obc_counter()
    print("\nAll tests passed.")