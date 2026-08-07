import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

from bus.virtual_bus import VirtualBus
from modules.kms import KMS
from modules.gateway_ecu import GatewayECU
from modules.bms_ecu import BMSECU
from attacker.attacker import Attacker


MASTER_KEY = b'secureev_master_key_32bytes!!!!!'


def make_system():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    gw  = GatewayECU(kms)
    atk = Attacker(bus)
    return bus, kms, gw, atk


def test_bms_spoof_blocked_by_gateway():
    bus, kms, gw, atk = make_system()
    frame  = atk.bms_spoof(999.9, 200.0, 0)
    result = gw.receive(frame)
    assert result is False
    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "mac_failure"
    print("PASS: BMS spoof blocked at Gateway")


def test_drive_by_wire_blocked_by_gateway():
    bus, kms, gw, atk = make_system()
    frame  = atk.drive_by_wire_inject(500.0, 3000, 3)
    result = gw.receive(frame)
    assert result is False
    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "mac_failure"
    print("PASS: drive-by-wire injection blocked")


def test_rogue_charging_blocked_by_gateway():
    bus, kms, gw, atk = make_system()
    frame  = atk.rogue_charging(0xAA, 32000)
    result = gw.receive(frame)
    assert result is False
    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "mac_failure"
    print("PASS: rogue charging station blocked")


def test_replay_blocked_by_gateway():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    bms = BMSECU(kms, bus)
    gw  = GatewayECU(kms)
    atk = Attacker(bus)

    # Transmit a legitimate frame
    frame = bms.transmit(400.0, 35.0, 85)
    gw.receive(frame)  # accepted first time

    # Capture and replay
    atk.capture(frame)
    replay_frame = atk.replay(
        atk.captured_frames[0]
    )
    result = gw.receive(replay_frame)

    assert result is False
    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "replay_attack"
    print("PASS: replay attack blocked by Gateway")


def test_can_flood_triggers_rate_limit():
    bus, kms, gw, atk = make_system()

    # BMS max rate is 110 frames/sec
    # Inject 200 frames instantly
    count = atk.can_flood(0x100, 200)
    assert count == 200

    # Send all frames through Gateway
    blocked = 0
    for frame in bus.frames:
        if not gw.receive(frame):
            blocked += 1

    # Most should be blocked by rate limit or MAC
    assert blocked > 0
    print(f"PASS: CAN flood — {blocked}/200 "
          f"frames blocked by Gateway")


def test_attacker_stats():
    bus, kms, gw, atk = make_system()
    atk.bms_spoof(999.9, 200.0, 0)
    atk.drive_by_wire_inject(500.0, 3000, 3)
    atk.rogue_charging(0xAA, 32000)

    stats = atk.stats()
    assert stats["total_attacks"] == 3
    print(f"PASS: attacker stats — "
          f"{stats['total_attacks']} attacks logged")


if __name__ == "__main__":
    print("Running Attacker tests...\n")
    test_bms_spoof_blocked_by_gateway()
    test_drive_by_wire_blocked_by_gateway()
    test_rogue_charging_blocked_by_gateway()
    test_replay_blocked_by_gateway()
    test_can_flood_triggers_rate_limit()
    test_attacker_stats()
    print("\nAll tests passed.")