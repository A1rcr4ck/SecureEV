import sys
import os
sys.path.insert(0, os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
))

from bus.virtual_bus import VirtualBus
from modules.kms import KMS
from modules.motor_ecu import MotorECU
from crypto.mac import verify_mac


MASTER_KEY = b'secureev_master_key_32bytes!!!!!'


def test_motor_transmit():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    motor = MotorECU(kms, bus)

    frame = motor.transmit(
        torque=150.0,
        speed=1200,
        mode=3
    )

    assert frame.can_id == 0x200
    assert frame.counter == 0
    assert len(frame.payload) == 4
    assert len(frame.mac) == 2
    assert len(bus.frames) == 1
    print("PASS: motor frame transmitted and stored")


def test_motor_mac():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    motor = MotorECU(kms, bus)

    frame = motor.transmit(150.0, 1200, 3)
    session_key = KMS(MASTER_KEY).get_session_key(0x200)

    result = verify_mac(
        session_key,
        frame.can_id,
        frame.counter,
        frame.payload,
        frame.mac
    )
    assert result, "Motor MAC verification failed"
    print("PASS: motor MAC verified")


def test_motor_payload_encoding():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    motor = MotorECU(kms, bus)

    frame = motor.transmit(150.0, 1200, 3)
    decoded = motor.decode_payload(frame.payload)

    assert decoded["torque"] == 150.0
    assert decoded["speed"] == 1200
    assert decoded["mode"] == "Drive"
    print("PASS: motor payload encoded and decoded")


def test_motor_negative_torque():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    motor = MotorECU(kms, bus)

    # Negative torque = regenerative braking
    frame = motor.transmit(-80.0, 800, 1)
    decoded = motor.decode_payload(frame.payload)

    assert decoded["torque"] == -80.0
    assert decoded["mode"] == "Reverse"
    print("PASS: negative torque (regen braking) encoded")


def test_motor_counter():
    bus = VirtualBus()
    kms = KMS(MASTER_KEY)
    motor = MotorECU(kms, bus)

    f1 = motor.transmit(100.0, 1000, 3)
    f2 = motor.transmit(110.0, 1100, 3)
    f3 = motor.transmit(120.0, 1200, 3)

    assert f1.counter == 0
    assert f2.counter == 1
    assert f3.counter == 2
    print("PASS: motor counter increments correctly")


if __name__ == "__main__":
    print("Running Motor ECU tests...\n")
    test_motor_transmit()
    test_motor_mac()
    test_motor_payload_encoding()
    test_motor_negative_torque()
    test_motor_counter()
    print("\nAll tests passed.")