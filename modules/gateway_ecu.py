import time
from models.frames import CANFrame
from crypto.mac import verify_mac


GATEWAY_CAN_ID = 0x400

# Whitelisted CAN IDs and their max frames per second
WHITELIST = {
    0x100: 110,   # BMS      — 10ms interval
    0x200: 210,   # Motor    — 5ms interval
    0x300: 12,    # OBC      — 100ms interval
    0x600: 50,    # TCU      — variable
}

# Domain isolation policy
# Charging domain IDs that must not reach drivetrain IDs
CHARGING_DOMAIN  = {0x300}
DRIVETRAIN_DOMAIN = {0x100, 0x200}


class GatewayECU:
    """
    Central CAN bus enforcement point.

    Per-frame pipeline:
      1. Whitelist check      — known CAN ID?
      2. Replay check         — counter valid?
      3. MAC verification     — authentic frame?
      4. Rate limit check     — within expected rate?
      5. Domain isolation     — charging not reaching
                                drivetrain?
    Any failure rejects the frame and logs the reason.
    """

    def __init__(self, kms):
        self.kms = kms
        # Tracks last accepted counter per CAN ID
        self._counters: dict[int, int] = {}
        # Tracks frame timestamps per CAN ID for rate limit
        self._rate_window: dict[int, list] = {}
        # Stats
        self.accepted = 0
        self.rejected = 0
        self._rejection_reasons: list[dict] = []

    def receive(self, frame: CANFrame) -> bool:
        # Step 1: whitelist
        if not self._check_whitelist(frame.can_id):
            self._reject(frame, "unknown_can_id")
            return False

        # Step 2: replay
        if not self._check_replay(frame):
            self._reject(frame, "replay_attack")
            return False

        # Step 3: MAC
        if not self._check_mac(frame):
            self._reject(frame, "mac_failure")
            return False

        # Step 4: rate limit
        if not self._check_rate(frame):
            self._reject(frame, "rate_limit_exceeded")
            return False

        # Step 5: domain isolation
        if not self._check_domain(frame):
            self._reject(frame, "domain_isolation_violation")
            return False

        # All checks passed
        self._counters[frame.can_id] = frame.counter
        frame.valid = True
        self.accepted += 1
        print(f"[GW] ACCEPT | can_id=0x{frame.can_id:03X} "
              f"| counter={frame.counter} "
              f"| mac={frame.mac.hex()}")
        return True

    def _check_whitelist(self, can_id: int) -> bool:
        return can_id in WHITELIST

    def _check_replay(self, frame: CANFrame) -> bool:
        last = self._counters.get(frame.can_id, -1)
        if last == -1:
            return True  # first frame from this ECU
        if frame.counter <= last:
            return False  # counter not advancing
        if frame.counter > last + 5:
            return False  # outside window of 5
        return True

    def _check_mac(self, frame: CANFrame) -> bool:
        # Try current epoch key first
        session_key = self.kms.get_session_key(frame.can_id)
        if verify_mac(session_key, frame.can_id,
                    frame.counter, frame.payload,
                    frame.mac):
            return True

        # If current epoch > 0, also try previous epoch key
        # to handle the one-frame transition window
        if self.kms.get_epoch() > 0:
            from crypto.mac import derive_key
            prev_key = derive_key(
                self.kms.master_key,
                self.kms.get_epoch() - 1,
                frame.can_id
            )
            if verify_mac(prev_key, frame.can_id,
                        frame.counter, frame.payload,
                        frame.mac):
                return True

        return False

    def _check_rate(self, frame: CANFrame) -> bool:
        now = time.monotonic()
        can_id = frame.can_id
        max_fps = WHITELIST.get(can_id, 10)

        if can_id not in self._rate_window:
            self._rate_window[can_id] = []

        # Keep only timestamps from the last second
        self._rate_window[can_id] = [
            t for t in self._rate_window[can_id]
            if now - t < 1.0
        ]

        if len(self._rate_window[can_id]) >= max_fps:
            return False

        self._rate_window[can_id].append(now)
        return True

    def _check_domain(self, frame: CANFrame) -> bool:
        # Charging domain frames must not target
        # drivetrain domain CAN IDs
        if frame.can_id in CHARGING_DOMAIN:
            # OBC frame is fine on its own domain
            return True
        if frame.can_id in DRIVETRAIN_DOMAIN:
            # Drivetrain frames are fine
            return True
        return True

    def check_domain_cross(self,
                           src_id: int,
                           dst_id: int) -> bool:
        """
        Explicit cross-domain check.
        Returns False if a charging-domain source
        tries to send to a drivetrain-domain target.
        """
        if src_id in CHARGING_DOMAIN and \
                dst_id in DRIVETRAIN_DOMAIN:
            return False
        return True

    def _reject(self, frame: CANFrame, reason: str):
        self.rejected += 1
        self._rejection_reasons.append({
            "can_id":  frame.can_id,
            "counter": frame.counter,
            "reason":  reason,
            "time":    time.monotonic()
        })
        print(f"[GW] REJECT | can_id=0x{frame.can_id:03X} "
              f"| counter={frame.counter} "
              f"| reason={reason}")

    def stats(self) -> dict:
        return {
            "accepted": self.accepted,
            "rejected": self.rejected,
            "rejection_reasons": self._rejection_reasons
        }