import hmac
import hashlib
import struct
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def compute_mac(session_key: bytes,
                can_id: int,
                counter: int,
                payload: bytes) -> bytes:
    message = (
        struct.pack(">I", can_id) +
        struct.pack(">H", counter) +
        payload
    )
    full_mac = hmac.new(
        session_key,
        message,
        hashlib.sha256
    ).digest()
    return full_mac[:2]


def verify_mac(session_key: bytes,
               can_id: int,
               counter: int,
               payload: bytes,
               received_mac: bytes) -> bool:
    expected = compute_mac(session_key, can_id,
                           counter, payload)
    return hmac.compare_digest(expected, received_mac)


def derive_key(master_key: bytes,
               epoch: int,
               can_id: int) -> bytes:
    info = struct.pack(">IH", can_id, epoch)
    salt = struct.pack(">H", epoch)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(master_key)