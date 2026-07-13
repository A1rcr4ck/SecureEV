from dataclasses import dataclass, field
from typing import Optional

@dataclass
class CANFrame:
    can_id:    int
    counter:   int
    payload:   bytes
    mac:       bytes
    timestamp: float
    valid:     bool = False

@dataclass
class KeyMaterial:
    session_key: bytes
    epoch:       int
    created_at:  float

@dataclass
class IDSAlert:
    alert_type: str
    can_id:     int
    frame:      CANFrame
    severity:   str
    timestamp:  float

@dataclass
class ForensicEntry:
    sequence:   int
    event_type: str
    data:       dict
    prev_hash:  bytes
    entry_hash: bytes
    timestamp:  float