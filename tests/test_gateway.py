import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

from bus.virtual_bus import VirtualBus
from modules.kms import KMS
from modules.bms_ecu import BMSECU
from modules.motor_ecu import MotorECU
from modules.obc_ecu import OBCECU
from modules.gateway_ecu import GatewayECU
from models.frames import CANFrame
from crypto.mac import compute_mac
import time


MASTER_KEY = b'secureev_master_key_32bytes!!!!!'


def test_gateway_accepts_valid_bms():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    bms = BMSECU(kms, bus)
    gw  = GatewayECU(KMS(MASTER_KEY))

    frame = bms.transmit(400.5, 35.0, 85)
    result = gw.receive(frame)

    assert result is True
    assert frame.valid is True
    assert gw.accepted == 1
    print("PASS: gateway accepts valid BMS frame")


def test_gateway_rejects_unknown_can_id():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    gw  = GatewayECU(KMS(MASTER_KEY))

    frame = CANFrame(
        can_id=0x999,
        counter=0,
        payload=b'\x00' * 4,
        mac=b'\x00\x00',
        timestamp=time.monotonic()
    )
    result = gw.receive(frame)

    assert result is False
    assert gw.rejected == 1
    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "unknown_can_id"
    print("PASS: unknown CAN ID rejected")


def test_gateway_rejects_replay():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    bms = BMSECU(kms, bus)
    gw  = GatewayECU(KMS(MASTER_KEY))

    frame = bms.transmit(400.5, 35.0, 85)
    gw.receive(frame)  # accept first time

    # Send same frame again (replay)
    result = gw.receive(frame)

    assert result is False
    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "replay_attack"
    print("PASS: replayed frame rejected")


def test_gateway_rejects_bad_mac():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    bms = BMSECU(kms, bus)
    gw  = GatewayECU(KMS(MASTER_KEY))

    frame = bms.transmit(400.5, 35.0, 85)
    # Tamper with the MAC
    frame.mac = b'\xDE\xAD'
    result = gw.receive(frame)

    assert result is False
    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "mac_failure"
    print("PASS: tampered MAC rejected")


def test_gateway_rejects_tampered_payload():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    bms = BMSECU(kms, bus)
    gw  = GatewayECU(KMS(MASTER_KEY))

    frame = bms.transmit(400.5, 35.0, 85)
    # Tamper with payload — MAC will no longer match
    frame.payload = b'\xFF\xFF\xFF\xFF'
    result = gw.receive(frame)

    assert result is False
    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "mac_failure"
    print("PASS: tampered payload rejected")


def test_gateway_domain_isolation():
    gw = GatewayECU(KMS(MASTER_KEY))

    # Charging domain (0x300) -> Drivetrain (0x200)
    # should be blocked
    result = gw.check_domain_cross(0x300, 0x200)
    assert result is False

    # Charging domain -> Charging domain: fine
    result = gw.check_domain_cross(0x300, 0x300)
    assert result is True

    # Drivetrain -> Drivetrain: fine
    result = gw.check_domain_cross(0x200, 0x100)
    assert result is True

    print("PASS: domain isolation policy enforced")


def test_gateway_accepts_multiple_ecus():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    bms   = BMSECU(kms, bus)
    motor = MotorECU(kms, bus)
    obc   = OBCECU(kms, bus, charger_allowlist=[0x01])
    gw    = GatewayECU(KMS(MASTER_KEY))

    f1 = bms.transmit(400.5, 35.0, 85)
    f2 = motor.transmit(150.0, 1200, 3)
    f3 = obc.transmit(16000, 0x01, 0x01)

    assert gw.receive(f1) is True
    assert gw.receive(f2) is True
    assert gw.receive(f3) is True
    assert gw.accepted == 3
    assert gw.rejected == 0
    print("PASS: gateway accepts all three ECU frames")


def test_gateway_stats():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    bms = BMSECU(kms, bus)
    gw  = GatewayECU(KMS(MASTER_KEY))

    frame = bms.transmit(400.5, 35.0, 85)
    gw.receive(frame)

    # Tampered frame
    frame2 = bms.transmit(401.0, 36.0, 84)
    frame2.mac = b'\x00\x00'
    gw.receive(frame2)

    stats = gw.stats()
    assert stats["accepted"] == 1
    assert stats["rejected"] == 1
    print("PASS: gateway stats tracked correctly")


if __name__ == "__main__":
    print("Running Gateway ECU tests...\n")
    test_gateway_accepts_valid_bms()
    test_gateway_rejects_unknown_can_id()
    test_gateway_rejects_replay()
    test_gateway_rejects_bad_mac()
    test_gateway_rejects_tampered_payload()
    test_gateway_domain_isolation()
    test_gateway_accepts_multiple_ecus()
    test_gateway_stats()
    print("\nAll tests passed.")