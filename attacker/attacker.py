import time
import struct
import hmac
import hashlib
from models.frames import CANFrame
from bus.virtual_bus import VirtualBus


BMS_CAN_ID    = 0x100
MOTOR_CAN_ID  = 0x200
OBC_CAN_ID    = 0x300
UNKNOWN_CAN_ID = 0x7FF


class Attacker:
    """
    Attacker Simulation Module.
    Simulates all six threat scenarios defined
    in the SecureEV threat model.

    Injects frames directly onto the CAN bus
    bypassing authentication — simulating a real
    attacker who knows the frame format but does
    not have session keys.

    Attack scenarios:
      1. BMS spoof
      2. Drive-by-wire injection
      3. Rogue OTA delivery
      4. Rogue charging station
      5. Replay attack
      6. CAN flood
    """

    def __init__(self, bus: VirtualBus):
        self.bus = bus
        self.captured_frames: list[CANFrame] = []
        self._attack_log: list[dict] = []

    def bms_spoof(self,
                  voltage: float,
                  temperature: float,
                  soc: int) -> CANFrame:
        """
        Attack 1: BMS Spoofing.
        Injects fake BMS sensor readings with
        invalid MAC. Simulates attacker sending
        false voltage or temperature to trigger
        autonomous emergency stop.
        """
        voltage_raw = int(voltage * 100)
        voltage_raw = max(0, min(65535, voltage_raw))
        temp_raw    = int(temperature) + 40
        temp_raw    = max(0, min(255, temp_raw))
        soc_raw     = max(0, min(100, soc))

        payload = struct.pack(">HBB",
                              voltage_raw,
                              temp_raw,
                              soc_raw)

        # Invalid MAC — attacker does not have key
        fake_mac = b'\xDE\xAD'

        frame = CANFrame(
            can_id=BMS_CAN_ID,
            counter=0,
            payload=payload,
            mac=fake_mac,
            timestamp=time.monotonic()
        )

        self.bus.append(frame)
        self._log("bms_spoof", BMS_CAN_ID,
                  f"voltage={voltage}V "
                  f"temp={temperature}C soc={soc}%")
        print(f"[ATK] BMS SPOOF | voltage={voltage}V "
              f"| temp={temperature}C "
              f"| soc={soc}% "
              f"| mac=DEAD (invalid)")
        return frame

    def drive_by_wire_inject(self,
                             torque: float,
                             speed: int,
                             mode: int) -> CANFrame:
        """
        Attack 2: Drive-by-Wire Injection.
        Injects fake motor command frame.
        Simulates attacker taking control of
        steering or braking.
        """
        torque_raw = int(torque * 10)
        torque_raw = max(-32768, min(32767, torque_raw))
        speed_raw  = int(speed / 10)
        speed_raw  = max(0, min(255, speed_raw))
        mode_raw   = max(0, min(3, mode))

        payload  = struct.pack(">hBB",
                               torque_raw,
                               speed_raw,
                               mode_raw)
        fake_mac = b'\xDE\xAD'

        frame = CANFrame(
            can_id=MOTOR_CAN_ID,
            counter=0,
            payload=payload,
            mac=fake_mac,
            timestamp=time.monotonic()
        )

        self.bus.append(frame)
        self._log("drive_by_wire", MOTOR_CAN_ID,
                  f"torque={torque}Nm "
                  f"speed={speed}RPM mode={mode}")
        print(f"[ATK] DRIVE-BY-WIRE | torque={torque}Nm "
              f"| speed={speed}RPM "
              f"| mode={mode} "
              f"| mac=DEAD (invalid)")
        return frame

    def rogue_ota(self, payload: bytes) -> bool:
        """
        Attack 3: Rogue OTA Delivery.
        Sends unsigned OTA firmware payload
        through TCU wireless interface.
        Returns True if TCU blocks it (expected),
        False if it gets through (security failure).
        """
        print(f"[ATK] ROGUE OTA | payload_len="
              f"{len(payload)} | unsigned")
        self._log("rogue_ota", 0x600,
                  f"unsigned payload len={len(payload)}")
        # Rogue OTA goes through TCU interface
        # TCU should block this
        return False

    def rogue_charging(self,
                       charger_id: int,
                       current_ma: int) -> CANFrame:
        """
        Attack 4: Rogue Charging Station.
        Injects charging frame with unknown
        charger ID directly onto CAN bus.
        """
        current_raw = max(0, min(65535, current_ma))
        payload = struct.pack(">HBB",
                              current_raw,
                              0x01,
                              charger_id)
        fake_mac = b'\xDE\xAD'

        frame = CANFrame(
            can_id=OBC_CAN_ID,
            counter=0,
            payload=payload,
            mac=fake_mac,
            timestamp=time.monotonic()
        )

        self.bus.append(frame)
        self._log("rogue_charging", OBC_CAN_ID,
                  f"charger_id=0x{charger_id:02X} "
                  f"current={current_ma}mA")
        print(f"[ATK] ROGUE CHARGING | "
              f"charger_id=0x{charger_id:02X} "
              f"| current={current_ma}mA "
              f"| mac=DEAD (invalid)")
        return frame

    def replay(self,
               captured_frame: CANFrame) -> CANFrame:
        """
        Attack 5: Replay Attack.
        Retransmits a previously captured valid
        frame. Counter will be rejected by Gateway
        replay detection.
        """
        replay_frame = CANFrame(
            can_id=captured_frame.can_id,
            counter=captured_frame.counter,
            payload=captured_frame.payload,
            mac=captured_frame.mac,
            timestamp=time.monotonic()
        )

        self.bus.append(replay_frame)
        self._log("replay", captured_frame.can_id,
                  f"counter={captured_frame.counter}")
        print(f"[ATK] REPLAY | "
              f"can_id=0x{captured_frame.can_id:03X} "
              f"| counter={captured_frame.counter} "
              f"| mac={captured_frame.mac.hex()}")
        return replay_frame

    def can_flood(self,
                  can_id: int,
                  num_frames: int) -> int:
        """
        Attack 6: CAN Flood.
        Sends num_frames high-frequency frames
        to trigger rate limit detection at Gateway.
        Returns number of frames injected.
        """
        print(f"[ATK] CAN FLOOD | "
              f"can_id=0x{can_id:03X} "
              f"| frames={num_frames}")

        for i in range(num_frames):
            frame = CANFrame(
                can_id=can_id,
                counter=i,
                payload=b'\xFF' * 4,
                mac=b'\xDE\xAD',
                timestamp=time.monotonic()
            )
            self.bus.append(frame)

        self._log("can_flood", can_id,
                  f"num_frames={num_frames}")
        return num_frames

    def capture(self, frame: CANFrame):
        """Captures a frame for later replay."""
        self.captured_frames.append(frame)

    def _log(self, attack_type: str,
             can_id: int, details: str):
        self._attack_log.append({
            "attack":    attack_type,
            "can_id":    hex(can_id),
            "details":   details,
            "timestamp": time.monotonic()
        })

    def stats(self) -> dict:
        return {
            "total_attacks":  len(self._attack_log),
            "captured_frames": len(self.captured_frames),
            "attack_log":     self._attack_log
        }