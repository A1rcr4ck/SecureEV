import struct
import time
from models.frames import CANFrame
from crypto.mac import compute_mac


OBC_CAN_ID = 0x300


class OBCECU:
    """
    Authenticated OBC / Charging ECU node.
    Transmits charging status frames every 100ms.
    Validates charger ID against allowlist before transmit.
    CAN ID: 0x300

    Payload layout (4 bytes):
      Byte 0-1 : uint16  charge current (mA)
      Byte 2   : uint8   charge state
                         0x00 = Idle
                         0x01 = Charging
                         0x02 = Fault
                         0x03 = Complete
      Byte 3   : uint8   charger ID
                         0x00 = No charger
                         0x01-0xFE = Known IDs
                         0xFF = Unknown / rejected
    """

    STATES = {
        0x00: "Idle",
        0x01: "Charging",
        0x02: "Fault",
        0x03: "Complete"
    }

    def __init__(self, kms, bus,
                 charger_allowlist: list = None):
        self.kms = kms
        self.bus = bus
        self.counter = 0
        self.charger_allowlist = charger_allowlist or [
            0x01, 0x02, 0x03
        ]

    def validate_charger(self, charger_id: int) -> bool:
        if charger_id == 0x00:
            return True  # no charger connected, always ok
        return charger_id in self.charger_allowlist

    def build_payload(self,
                      current_ma: int,
                      state: int,
                      charger_id: int) -> bytes:
        current_raw = max(0, min(65535, current_ma))
        state_raw   = max(0, min(3, state))
        id_raw      = max(0, min(255, charger_id))

        return struct.pack(">HBB",
                           current_raw,
                           state_raw,
                           id_raw)

    def transmit(self,
                 current_ma: int,
                 state: int,
                 charger_id: int):
        if not self.validate_charger(charger_id):
            print(f"[OBC] BLOCKED | charger_id=0x"
                  f"{charger_id:02X} not in allowlist")
            return None

        session_key = self.kms.get_session_key(OBC_CAN_ID)
        payload = self.build_payload(current_ma,
                                     state, charger_id)
        mac = compute_mac(session_key, OBC_CAN_ID,
                          self.counter, payload)

        frame = CANFrame(
            can_id=OBC_CAN_ID,
            counter=self.counter,
            payload=payload,
            mac=mac,
            timestamp=time.monotonic()
        )

        self.bus.append(frame)
        self.kms.tick()
        self.counter = (self.counter + 1) % 65536

        print(f"[OBC] TX | counter={frame.counter} "
              f"| current={current_ma}mA "
              f"| state={self.STATES.get(state, '?')} "
              f"| charger_id=0x{charger_id:02X} "
              f"| mac={mac.hex()}")

        return frame

    def decode_payload(self, payload: bytes) -> dict:
        current_raw, state, charger_id = struct.unpack(
            ">HBB", payload
        )
        return {
            "current_ma": current_raw,
            "state":      self.STATES.get(state, "unknown"),
            "charger_id": charger_id
        }