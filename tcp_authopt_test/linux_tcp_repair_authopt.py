# SPDX-License-Identifier: GPL-2.0
import errno
import socket
import struct
from dataclasses import dataclass

TCP_REPAIR_AUTHOPT = 40


@dataclass
class tcp_repair_authopt:
    """Like linux struct tcp_authopt"""

    src_isn: int = 0
    dst_isn: int = 0
    snd_sne: int = 0
    rcv_sne: int = 0
    snd_seq: int = 0
    rcv_seq: int = 0

    struct_format = "IIIIII"
    sizeof = struct.calcsize(struct_format)

    def pack(self) -> bytes:
        return struct.pack(
            self.struct_format,
            self.src_isn,
            self.dst_isn,
            self.snd_sne,
            self.rcv_sne,
            self.snd_seq,
            self.rcv_seq,
        )

    def __bytes__(self):
        return self.pack()

    @classmethod
    def unpack(cls, b: bytes):
        tup = struct.unpack(cls.struct_format, b)
        return cls(*tup)


def get_tcp_repair_authopt(sock: socket.socket) -> tcp_repair_authopt:
    b = sock.getsockopt(socket.SOL_TCP, TCP_REPAIR_AUTHOPT, tcp_repair_authopt.sizeof)
    return tcp_repair_authopt.unpack(b)


def set_tcp_repair_authopt(sock: socket.socket, opt: tcp_repair_authopt):
    sock.setsockopt(socket.SOL_TCP, TCP_REPAIR_AUTHOPT, opt.pack())


def has_tcp_repair_authopt_on_sock(sock: socket.socket) -> bool:
    """Check if TCP_REPAIR_AUTHOPT is supported"""
    try:
        get_tcp_repair_authopt(sock)
        return True
    except OSError as e:
        if e.errno == errno.ENOPROTOOPT:
            return False
        # Return True if tcp_authopt supported but not enabled for this specific socket
        if e.errno == errno.ENOENT:
            return False
        raise


def has_tcp_repair_authopt() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return has_tcp_repair_authopt_on_sock(sock)
