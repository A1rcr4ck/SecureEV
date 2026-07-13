from models.frames import CANFrame
from typing import Callable


class VirtualBus:
    """
    Simple in-memory virtual CAN bus.
    Frames are appended to a list.
    Subscribers receive frames via callbacks.
    """

    def __init__(self):
        self.frames: list[CANFrame] = []
        self._subscribers: list[Callable] = []

    def append(self, frame: CANFrame):
        self.frames.append(frame)
        for cb in self._subscribers:
            cb(frame)

    def subscribe(self, callback: Callable):
        self._subscribers.append(callback)

    def clear(self):
        self.frames.clear()