import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

import hmac
import hashlib
from bus.virtual_bus import VirtualBus
from modules.kms import KMS
from modules.gateway_ecu import GatewayECU
from modules.tcu import TCU, OTA_SIGNING_KEY


MASTER_KEY = b'secureev_master_key_32bytes!!!!!'


def make_tcu():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    gw  = GatewayECU(kms)
    tcu = TCU(kms, gw)
    return tcu, gw, kms


def make_signed_ota(data: bytes) -> bytes:
    """Helper: build a valid signed OTA payload."""
    sig = hmac.new(
        OTA_SIGNING_KEY, data, hashlib.sha256
    ).digest()[:4]
    return b'SIGN' + data + sig


def test_valid_ota_forwarded():
    tcu, _, _ = make_tcu()
    payload = make_signed_ota(b'fw_v2')
    result  = tcu.receive_wireless("ota", payload,
                                   "update_server")
    assert result is True
    assert tcu.forwarded == 1
    assert tcu.blocked   == 0
    print("PASS: valid signed OTA forwarded")


def test_unsigned_ota_blocked():
    tcu, _, _ = make_tcu()
    payload = b'malicious_firmware_data'
    result  = tcu.receive_wireless("ota", payload,
                                   "rogue_server")
    assert result is False
    assert tcu.blocked == 1
    log = tcu.stats()["block_log"]
    assert log[0]["reason"] == "ota_unsigned" or \
           log[0]["reason"] == "not_in_allowlist"
    print("PASS: unsigned OTA blocked")


def test_known_charger_forwarded():
    tcu, _, _ = make_tcu()
    # charger ID 0x01 is in KNOWN_CHARGER_IDS
    payload = bytes([0x01]) + b'\x00' * 3
    result  = tcu.receive_wireless("charging", payload,
                                   "charger_01")
    assert result is True
    assert tcu.forwarded == 1
    print("PASS: known charger forwarded")


def test_rogue_charger_blocked():
    tcu, _, _ = make_tcu()
    # charger ID 0xAA is not in KNOWN_CHARGER_IDS
    payload = bytes([0xAA]) + b'\x00' * 3
    result  = tcu.receive_wireless("charging", payload,
                                   "rogue_charger")
    assert result is False
    assert tcu.blocked == 1
    log = tcu.stats()["block_log"]
    assert "charger" in log[0]["reason"] or \
           "allowlist" in log[0]["reason"]
    print("PASS: rogue charger blocked")


def test_unknown_type_blocked():
    tcu, _, _ = make_tcu()
    result = tcu.receive_wireless("unknown_protocol",
                                  b'\x00' * 4,
                                  "unknown_source")
    assert result is False
    assert tcu.blocked == 1
    print("PASS: unknown message type blocked")


def test_bluetooth_forwarded():
    tcu, _, _ = make_tcu()
    payload = b'\x01\x02\x03\x04'
    result  = tcu.receive_wireless("bluetooth", payload,
                                   "bt_device")
    assert result is True
    assert tcu.forwarded == 1
    print("PASS: bluetooth command forwarded")


def test_ota_tampered_payload_blocked():
    tcu, _, _ = make_tcu()
    # Valid signature but tampered data
    payload = make_signed_ota(b'fw_v2')
    # Corrupt one byte in the data section
    payload = bytearray(payload)
    payload[5] = 0xFF
    payload = bytes(payload)
    result = tcu.receive_wireless("ota", payload,
                                  "rogue_server")
    assert result is False
    print("PASS: tampered OTA payload blocked")


def test_tcu_stats():
    tcu, _, _ = make_tcu()
    # One valid, one blocked
    tcu.receive_wireless("charging",
                         bytes([0x01]) + b'\x00' * 3,
                         "charger_01")
    tcu.receive_wireless("charging",
                         bytes([0xAA]) + b'\x00' * 3,
                         "rogue")
    stats = tcu.stats()
    assert stats["forwarded"] == 1
    assert stats["blocked"]   == 1
    print("PASS: TCU stats tracked correctly")


if __name__ == "__main__":
    print("Running TCU tests...\n")
    test_valid_ota_forwarded()
    test_unsigned_ota_blocked()
    test_known_charger_forwarded()
    test_rogue_charger_blocked()
    test_unknown_type_blocked()
    test_bluetooth_forwarded()
    test_ota_tampered_payload_blocked()
    test_tcu_stats()
    print("\nAll tests passed.")