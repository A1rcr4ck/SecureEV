import struct
import time
from models.frames import CANFrame
from crypto.mac import compute_mac


MOTOR_CAN_ID = 0x200


class MotorECU:
    """
    Authenticated Motor Controller ECU node.
    Transmits drive-by-wire command frames every 5ms.
    CAN ID: 0x200

    Payload layout (4 bytes):
      Byte 0-1 : int16  torque command (Nm * 10)
      Byte 2   : uint8  speed (RPM / 10)
      Byte 3   : uint8  drive mode (0=Park, 1=Rev,
                                    2=Neutral, 3=Drive)
    """

    MODES = {0: "Park", 1: "Reverse",
             2: "Neutral", 3: "Drive"}

    def __init__(self, kms, bus):
        self.kms = kms
        self.bus = bus
        self.counter = 0

    def build_payload(self,
                      torque: float,
                      speed: int,
                      mode: int) -> bytes:
        # torque: float (Nm) -> int16 * 10
        torque_raw = int(torque * 10)
        torque_raw = max(-32768, min(32767, torque_raw))

        # speed: int (RPM) -> uint8 (RPM / 10)
        speed_raw = int(speed / 10)
        speed_raw = max(0, min(255, speed_raw))

        # mode: 0-3
        mode_raw = max(0, min(3, mode))

        return struct.pack(">hBB",
                           torque_raw,
                           speed_raw,
                           mode_raw)

    def transmit(self,
                 torque: float,
                 speed: int,
                 mode: int) -> CANFrame:
        session_key = self.kms.get_session_key(
            MOTOR_CAN_ID
        )
        payload = self.build_payload(torque, speed, mode)
        mac = compute_mac(session_key, MOTOR_CAN_ID,
                          self.counter, payload)

        frame = CANFrame(
            can_id=MOTOR_CAN_ID,
            counter=self.counter,
            payload=payload,
            mac=mac,
            timestamp=time.monotonic()
        )

        self.bus.append(frame)
        self.kms.tick()
        self.counter = (self.counter + 1) % 65536

        print(f"[Motor] TX | counter={frame.counter} "
              f"| torque={torque}Nm "
              f"| speed={speed}RPM "
              f"| mode={self.MODES.get(mode, '?')} "
              f"| mac={mac.hex()}")

        return frame

    def decode_payload(self, payload: bytes) -> dict:
        torque_raw, speed_raw, mode = struct.unpack(
            ">hBB", payload
        )
        return {
            "torque": torque_raw / 10,
            "speed":  speed_raw * 10,
            "mode":   self.MODES.get(mode, "unknown")
        }