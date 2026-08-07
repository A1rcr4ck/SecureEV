import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

import time
from bus.virtual_bus import VirtualBus
from modules.kms import KMS
from modules.bms_ecu import BMSECU
from modules.motor_ecu import MotorECU
from modules.obc_ecu import OBCECU
from modules.gateway_ecu import GatewayECU
from modules.tcu import TCU
from attacker.attacker import Attacker


MASTER_KEY = b'secureev_master_key_32bytes!!!!!'


def make_system(rotation_interval=1000):
    bus = VirtualBus()
    kms = KMS(MASTER_KEY,
              rotation_interval=rotation_interval)
    gw  = GatewayECU(kms)
    bms = BMSECU(kms, bus)
    motor = MotorECU(kms, bus)
    obc = OBCECU(kms, bus,
                 charger_allowlist=[0x01, 0x02])
    tcu = TCU(kms, gw)
    atk = Attacker(bus)
    return bus, kms, gw, bms, motor, obc, tcu, atk


def test_normal_traffic_all_accepted():
    """
    All legitimate ECU frames from BMS, Motor,
    and OBC must be accepted by the Gateway.
    """
    _, kms, gw, bms, motor, obc, _, _ = \
        make_system()

    results = []
    for i in range(5):
        f1 = bms.transmit(400.0 + i, 35.0, 85)
        f2 = motor.transmit(150.0, 1200, 3)
        f3 = obc.transmit(16000, 0x01, 0x01)
        results.append(gw.receive(f1))
        results.append(gw.receive(f2))
        results.append(gw.receive(f3))

    assert all(results)
    assert gw.accepted == 15
    assert gw.rejected == 0
    print("PASS: 15 legitimate frames — all accepted")


def test_attack_mixed_with_normal_traffic():
    """
    Attacker frames injected alongside legitimate
    traffic. Legitimate frames must be accepted,
    attack frames must be rejected.
    """
    bus, kms, gw, bms, motor, obc, _, atk = \
        make_system()

    accepted = 0
    rejected = 0

    for i in range(5):
        # Legitimate BMS frame
        f = bms.transmit(400.0 + i, 35.0, 85)
        if gw.receive(f):
            accepted += 1

        # Attacker injects fake BMS frame
        fake = atk.bms_spoof(999.9, 200.0, 0)
        if not gw.receive(fake):
            rejected += 1

        # Legitimate Motor frame
        f2 = motor.transmit(150.0, 1200, 3)
        if gw.receive(f2):
            accepted += 1

        # Attacker injects drive-by-wire
        fake2 = atk.drive_by_wire_inject(
            500.0, 3000, 3
        )
        if not gw.receive(fake2):
            rejected += 1

    assert accepted == 10
    assert rejected == 10
    print(f"PASS: mixed traffic — "
          f"{accepted} legitimate accepted, "
          f"{rejected} attacks rejected")


def test_replay_attack_during_normal_operation():
    """
    Attacker captures a legitimate frame and
    replays it after the next frame is accepted.
    Replay must be rejected.
    """
    bus, kms, gw, bms, _, _, _, atk = make_system()

    # Send first frame — accepted
    f1 = bms.transmit(400.0, 35.0, 85)
    assert gw.receive(f1) is True

    # Capture it
    atk.capture(f1)

    # Send second frame — accepted
    f2 = bms.transmit(401.0, 35.0, 84)
    assert gw.receive(f2) is True

    # Replay first frame — must be rejected
    replay = atk.replay(atk.captured_frames[0])
    assert gw.receive(replay) is False

    reasons = gw.stats()["rejection_reasons"]
    assert reasons[0]["reason"] == "replay_attack"
    print("PASS: replay attack rejected during "
          "normal operation")


def test_tcu_blocks_rogue_ota_end_to_end():
    """
    Rogue OTA from attacker must be blocked at TCU
    before reaching the authenticated CAN domain.
    """
    _, kms, gw, _, _, _, tcu, _ = make_system()

    # Unsigned rogue OTA payload
    rogue_payload = b'malicious_firmware_data_here'
    result = tcu.receive_wireless(
        "ota", rogue_payload, "rogue_server"
    )

    assert result is False
    assert tcu.blocked == 1
    assert gw.accepted == 0
    print("PASS: rogue OTA blocked at TCU, "
          "CAN domain untouched")


def test_tcu_valid_ota_reaches_gateway():
    """
    Valid signed OTA must pass TCU and reach Gateway.
    """
    import hmac as hmac_lib
    import hashlib
    from modules.tcu import OTA_SIGNING_KEY

    _, kms, gw, _, _, _, tcu, _ = make_system()

    data = b'fw_v2_valid'
    sig  = hmac_lib.new(
        OTA_SIGNING_KEY, data, hashlib.sha256
    ).digest()[:4]
    valid_payload = b'SIGN' + data + sig

    result = tcu.receive_wireless(
        "ota", valid_payload, "update_server"
    )

    assert result is True
    assert tcu.forwarded == 1
    print("PASS: valid OTA passed TCU and "
          "reached Gateway")


def test_key_rotation_during_operation():
    """
    Key rotation must not drop any legitimate frames.
    All frames across rotation boundary must be
    accepted.
    """
    bus, kms, gw, bms, _, _, _, _ = \
        make_system(rotation_interval=5)

    accepted = 0
    for i in range(15):
        f = bms.transmit(400.0 + i, 35.0, 85)
        if gw.receive(f):
            accepted += 1

    assert accepted == 15
    assert kms.get_epoch() >= 1
    print(f"PASS: {accepted}/15 frames accepted "
          f"across {kms.get_epoch()} key rotation(s)")


def test_domain_isolation_charging_blocked():
    """
    Charging domain frames must not reach
    drivetrain domain — domain isolation policy.
    """
    _, kms, gw, _, _, _, _, _ = make_system()

    # Direct cross-domain check
    result = gw.check_domain_cross(0x300, 0x200)
    assert result is False

    result = gw.check_domain_cross(0x300, 0x100)
    assert result is False

    result = gw.check_domain_cross(0x200, 0x100)
    assert result is True

    print("PASS: charging-to-drivetrain domain "
          "isolation enforced")


def test_full_system_summary():
    """
    Full system run — all ECUs transmitting,
    attacker injecting all six attack types,
    TCU filtering wireless traffic.
    Prints final stats.
    """
    import hmac as hmac_lib
    import hashlib
    from modules.tcu import OTA_SIGNING_KEY

    bus, kms, gw, bms, motor, obc, tcu, atk = \
        make_system(rotation_interval=10)

    gw_accepted = 0
    gw_rejected = 0

    print("\n--- Full System Run ---")

    # Normal ECU traffic
    for i in range(10):
        f1 = bms.transmit(400.0 + i*0.5, 35.0, 85-i)
        f2 = motor.transmit(150.0 + i, 1200, 3)
        f3 = obc.transmit(16000, 0x01, 0x01)
        for f in [f1, f2, f3]:
            if gw.receive(f):
                gw_accepted += 1

    # Attack 1: BMS spoof
    fake = atk.bms_spoof(999.9, 200.0, 0)
    if not gw.receive(fake):
        gw_rejected += 1

    # Attack 2: Drive-by-wire
    fake = atk.drive_by_wire_inject(500.0, 3000, 3)
    if not gw.receive(fake):
        gw_rejected += 1

    # Attack 3: Rogue OTA via TCU
    rogue = b'malicious_firmware'
    tcu.receive_wireless("ota", rogue, "rogue")

    # Attack 4: Rogue charging
    fake = atk.rogue_charging(0xAA, 32000)
    if not gw.receive(fake):
        gw_rejected += 1

    # Attack 5: Replay
    captured = bus.frames[0]
    atk.capture(captured)
    replay = atk.replay(atk.captured_frames[0])
    if not gw.receive(replay):
        gw_rejected += 1

    # Attack 6: CAN flood
    atk.can_flood(0x100, 20)
    for f in bus.frames[-20:]:
        if not gw.receive(f):
            gw_rejected += 1

    print(f"\n--- System Summary ---")
    print(f"Gateway accepted : {gw_accepted}")
    print(f"Gateway rejected : {gw_rejected}")
    print(f"TCU forwarded    : {tcu.forwarded}")
    print(f"TCU blocked      : {tcu.blocked}")
    print(f"KMS epoch        : {kms.get_epoch()}")
    print(f"KMS rotations    : "
          f"{len(kms.get_rotation_log())}")
    print(f"Attacks logged   : "
          f"{atk.stats()['total_attacks']}")

    assert gw_accepted == 30
    assert gw_rejected > 0
    assert tcu.blocked == 1
    print("\nPASS: full system integration test")


if __name__ == "__main__":
    print("Running Integration Tests...\n")
    test_normal_traffic_all_accepted()
    test_attack_mixed_with_normal_traffic()
    test_replay_attack_during_normal_operation()
    test_tcu_blocks_rogue_ota_end_to_end()
    test_tcu_valid_ota_reaches_gateway()
    test_key_rotation_during_operation()
    test_domain_isolation_charging_blocked()
    test_full_system_summary()
    print("\nAll integration tests passed.")