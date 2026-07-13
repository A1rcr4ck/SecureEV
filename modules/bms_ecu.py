import struct
import time
from models.frames import CANFrame
from crypto.mac import compute_mac


BMS_CAN_ID = 0x100


class BMSECU:
    """
    Authenticated BMS ECU node.
    Transmits voltage, temperature, and SOC readings
    as HMAC-signed CAN frames every 10ms.
    CAN ID: 0x100
    """

    def __init__(self, kms, bus):
        self.kms = kms
        self.bus = bus
        self.counter = 0

    def build_payload(self,
                      voltage: float,
                      temperature: float,
                      soc: int) -> bytes:
        # voltage: float (V) -> uint16 * 100
        # temperature: float (C) -> int8 with +40 offset
        # soc: int (0-100) -> uint8
        voltage_raw = int(voltage * 100)
        voltage_raw = max(0, min(65535, voltage_raw))

        temp_raw = int(temperature) + 40
        temp_raw = max(0, min(255, temp_raw))

        soc_raw = max(0, min(100, soc))

        payload = struct.pack(">HBB",
                              voltage_raw,
                              temp_raw,
                              soc_raw)
        return payload

    def transmit(self,
                 voltage: float,
                 temperature: float,
                 soc: int) -> CANFrame:
        session_key = self.kms.get_session_key(BMS_CAN_ID)
        payload = self.build_payload(voltage,
                                     temperature, soc)
        mac = compute_mac(session_key, BMS_CAN_ID,
                          self.counter, payload)

        frame = CANFrame(
            can_id=BMS_CAN_ID,
            counter=self.counter,
            payload=payload,
            mac=mac,
            timestamp=time.monotonic()
        )

        self.bus.append(frame)
        self.kms.tick()
        self.counter = (self.counter + 1) % 65536

        print(f"[BMS] TX | counter={frame.counter} "
              f"| voltage={voltage}V "
              f"| temp={temperature}C "
              f"| soc={soc}% "
              f"| mac={mac.hex()}")

        return frame

    def decode_payload(self, payload: bytes) -> dict:
        voltage_raw, temp_raw, soc = struct.unpack(
            ">HBB", payload
        )
        return {
            "voltage":     voltage_raw / 100,
            "temperature": temp_raw - 40,
            "soc":         soc
        }