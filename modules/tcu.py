import time
import hashlib
import hmac
from models.frames import CANFrame
from crypto.mac import compute_mac


TCU_CAN_ID = 0x600

# Allowed message types that can enter the CAN domain
ALLOWED_TYPES = [
    "ota_signed",
    "charging_known",
    "bt_command"
]

# Known valid charger IDs
KNOWN_CHARGER_IDS = [0x01, 0x02, 0x03]

# Simulated OTA signing key (in real deployment
# this would be a manufacturer public key)
OTA_SIGNING_KEY = b'secureev_ota_signing_key_32bytes'


class TCU:
    """
    Telematics Control Unit — Wireless Trust Boundary.
    Module 6.

    All wireless messages hit this module first.
    Only allowlisted, classified, validated messages
    are forwarded to the authenticated CAN domain.

    Pipeline per message:
      1. Classify message type
      2. Check against allowlist
      3. Validate OTA signature if OTA type
      4. Validate charger ID if charging type
      5. Forward to Gateway as CAN frame
      6. Block and log if any check fails
    """

    def __init__(self, kms, gateway):
        self.kms = kms
        self.gateway = gateway
        self.blocked = 0
        self.forwarded = 0
        self._block_log: list[dict] = []

    def receive_wireless(self,
                         msg_type: str,
                         payload: bytes,
                         source_id: str = "unknown") -> bool:
        """
        Entry point for all wireless messages.
        Returns True if forwarded to CAN, False if blocked.
        """
        print(f"[TCU] RX | type={msg_type} "
              f"| source={source_id} "
              f"| payload_len={len(payload)}")

        # Step 1: Classify
        classification = self.classify(msg_type, payload,
                                       source_id)

        # Step 2: Check allowlist
        if classification not in ALLOWED_TYPES:
            self._block(msg_type, source_id,
                        "not_in_allowlist")
            return False

        # Step 3: OTA validation
        if classification == "ota_signed":
            if not self.validate_ota(payload):
                self._block(msg_type, source_id,
                            "ota_signature_invalid")
                return False

        # Step 4: Charger ID validation
        if classification == "charging_known":
            charger_id = int.from_bytes(payload[:1],
                                        "big")
            if charger_id not in KNOWN_CHARGER_IDS:
                self._block(msg_type, source_id,
                            "unknown_charger_id")
                return False

        # Step 5: Forward to CAN
        frame = self.forward_to_can(classification,
                                    payload)
        result = self.gateway.receive(frame)
        if result:
            self.forwarded += 1
            print(f"[TCU] FORWARDED | type={classification}"
                  f" | can_id=0x{frame.can_id:03X}")
        return result

    def classify(self,
                 msg_type: str,
                 payload: bytes,
                 source_id: str) -> str:
        """
        Classifies incoming wireless message.
        Returns classification string.
        """
        if msg_type == "ota":
            # Check if payload contains signature marker
            if len(payload) >= 4 and \
                    payload[:4] == b'SIGN':
                return "ota_signed"
            return "ota_unsigned"

        if msg_type == "charging":
            charger_id = int.from_bytes(
                payload[:1], "big"
            ) if payload else 0xFF
            if charger_id in KNOWN_CHARGER_IDS:
                return "charging_known"
            return "charging_rogue"

        if msg_type == "bluetooth":
            return "bt_command"

        return "unknown"

    def validate_ota(self, payload: bytes) -> bool:
        """
        Validates OTA payload signature.
        Expects: SIGN (4 bytes) + data + HMAC (4 bytes)
        Returns True if signature is valid.
        """
        if len(payload) < 8:
            return False

        # Extract components
        marker  = payload[:4]    # b'SIGN'
        data    = payload[4:-4]  # actual firmware data
        sig     = payload[-4:]   # 4-byte signature

        if marker != b'SIGN':
            return False

        # Verify HMAC over data
        expected_sig = hmac.new(
            OTA_SIGNING_KEY,
            data,
            hashlib.sha256
        ).digest()[:4]

        return hmac.compare_digest(expected_sig, sig)

    def forward_to_can(self,
                       classification: str,
                       payload: bytes) -> CANFrame:
        """
        Wraps validated wireless payload as CAN frame
        and forwards to Gateway.
        """
        # Truncate or pad payload to 4 bytes
        can_payload = (payload[:4]).ljust(4, b'\x00') \
            if len(payload) >= 4 \
            else payload.ljust(4, b'\x00')

        session_key = self.kms.get_session_key(
            TCU_CAN_ID
        )

        # Use a simple incrementing counter for TCU
        counter = int(time.monotonic() * 1000) % 65536

        mac = compute_mac(session_key, TCU_CAN_ID,
                          counter, can_payload)

        return CANFrame(
            can_id=TCU_CAN_ID,
            counter=counter,
            payload=can_payload,
            mac=mac,
            timestamp=time.monotonic()
        )

    def _block(self, msg_type: str,
               source_id: str, reason: str):
        self.blocked += 1
        self._block_log.append({
            "msg_type":  msg_type,
            "source_id": source_id,
            "reason":    reason,
            "timestamp": time.monotonic()
        })
        print(f"[TCU] BLOCKED | type={msg_type} "
              f"| source={source_id} "
              f"| reason={reason}")

    def stats(self) -> dict:
        return {
            "forwarded":  self.forwarded,
            "blocked":    self.blocked,
            "block_log":  self._block_log
        }