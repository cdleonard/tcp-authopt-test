"""pack/unpack wrappers for sockaddr"""
import socket
import struct
from dataclasses import dataclass
from ipaddress import IPv4Address


@dataclass
class sockaddr_in:
    port: int
    addr: IPv4Address
    sizeof = 8

    def __init__(self, port=0, addr=None):
        self.port = port
        if addr is None:
            addr = IPv4Address(0)
        self.addr = IPv4Address(addr)

    def pack(self):
        return struct.pack("HH4s", socket.AF_INET, self.port, self.addr.packed)

    @classmethod
    def unpack(cls, buffer):
        family, port, addr_packed = struct.unpack("HH4s", buffer[:8])
        if family != socket.AF_INET:
            raise ValueError(f"Must be AF_INET not {family}")
        return cls(port, addr_packed)

    def __bytes__(self):
        return self.pack()


@dataclass
class sockaddr_storage:
    family: int
    data: bytes
    sizeof = 128

    def pack(self):
        return struct.pack("H126s", self.family, self.data)

    def __bytes__(self):
        return self.pack()

    @classmethod
    def unpack(cls, buffer):
        return cls(*struct.unpack("H126s", buffer))


def sockaddr_unpack(buffer: bytes):
    """Unpack based on family"""
    family = struct.unpack("H", buffer[:2])[0]
    if family == socket.AF_INET:
        return sockaddr_in.unpack(buffer)
    else:
        return sockaddr_storage.unpack(buffer)
