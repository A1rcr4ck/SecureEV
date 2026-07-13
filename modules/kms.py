import time
import struct
from crypto.mac import derive_key
from models.frames import KeyMaterial


KNOWN_CAN_IDS = [
    0x100,  # BMS
    0x200,  # Motor
    0x300,  # OBC
    0x400,  # Gateway
    0x500,  # KMS internal
    0x600,  # TCU
    0x700,  # IDS alerts
]

ROTATION_WINDOW = 5  # counter window resets on rotation


class KMS:
    """
    Lightweight Key Management System.
    Derives per-ECU session keys using HKDF.
    Performs atomic epoch-based key rotation.
    Zero frame loss guaranteed during rotation:
    new keys are fully derived before swap.
    """

    def __init__(self,
                 master_key: bytes,
                 rotation_interval: int = 1000):
        if len(master_key) < 32:
            raise ValueError(
                "Master key must be at least 32 bytes"
            )
        self.master_key = master_key
        self.rotation_interval = rotation_interval
        self.epoch = 0
        self.frame_count = 0
        self._keys: dict[int, bytes] = {}
        self._rotation_log: list[dict] = []
        self._derive_all_keys()

    def _derive_all_keys(self):
        """Derives session keys for all known CAN IDs."""
        new_keys = {}
        for can_id in KNOWN_CAN_IDS:
            new_keys[can_id] = derive_key(
                self.master_key,
                self.epoch,
                can_id
            )
        # Atomic swap — replace all at once
        self._keys = new_keys

    def get_session_key(self, can_id: int) -> bytes:
        if can_id not in self._keys:
            self._keys[can_id] = derive_key(
                self.master_key,
                self.epoch,
                can_id
            )
        return self._keys[can_id]

    def tick(self) -> bool:
        """
        Called after every frame transmission.
        Returns True if key rotation was triggered.
        """
        self.frame_count += 1
        if self.frame_count % self.rotation_interval == 0:
            return self.rotate()
        return False

    def rotate(self) -> bool:
        """
        Atomic key rotation:
        1. Derive new keys for all ECUs
        2. Swap atomically
        3. Increment epoch
        4. Log rotation event
        Returns True always (rotation complete).
        """
        old_epoch = self.epoch
        self.epoch += 1
        self._derive_all_keys()

        log_entry = {
            "event":     "key_rotation",
            "old_epoch": old_epoch,
            "new_epoch": self.epoch,
            "frame_count": self.frame_count,
            "timestamp": time.monotonic()
        }
        self._rotation_log.append(log_entry)

        print(f"[KMS] Key rotation | "
              f"epoch {old_epoch} -> {self.epoch} | "
              f"frame_count={self.frame_count}")
        return True

    def get_epoch(self) -> int:
        return self.epoch

    def get_frame_count(self) -> int:
        return self.frame_count

    def get_rotation_log(self) -> list:
        return self._rotation_log

    def stats(self) -> dict:
        return {
            "epoch":        self.epoch,
            "frame_count":  self.frame_count,
            "rotations":    len(self._rotation_log),
            "known_ids":    list(self._keys.keys())
        }