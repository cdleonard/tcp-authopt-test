"""Python wrapper around linux TCP_AUTHOPT ABI"""

import socket
import logging
import ctypes
from ctypes import c_uint32, c_uint8, c_byte, c_uint16

logger = logging.getLogger(__name__)

TCP_AUTHOPT = 38
TCP_AUTHOPT_KEY = 39

TCP_AUTHOPT_MAXKEYLEN = 80

TCP_AUTHOPT_KEY_DEL = 1 << 0
TCP_AUTHOPT_KEY_EXCLUDE_OPTS = 1 << 1

TCP_AUTHOPT_ALG_HMAC_SHA_1_96 = 1
TCP_AUTHOPT_ALG_AES_128_CMAC_96 = 2


class tcp_authopt(ctypes.Structure):
    """Like linux struct tcp_authopt"""

    _fields_ = [
        ("flags", c_uint32),
        ("send_local_id", c_uint32),
    ]

    def pack(self) -> bytes:
        return bytes(self)


def set_tcp_authopt(sock, opt: tcp_authopt):
    return sock.setsockopt(socket.IPPROTO_TCP, TCP_AUTHOPT, bytes(opt))


_keybuf = c_byte * TCP_AUTHOPT_MAXKEYLEN


class tcp_authopt_key(ctypes.Structure):
    """Like linux struct tcp_authopt_key"""

    _fields_ = [
        ("flags", c_uint32),
        ("local_id", c_uint32),
        ("send_id", c_uint8),
        ("recv_id", c_uint8),
        ("alg", c_uint8),
        ("keylen", c_uint8),
        ("keybuf", _keybuf),
    ]

    def __init__(
        self,
        flags: int = 0,
        local_id: int = 0,
        send_id: int = 0,
        recv_id: int = 0,
        alg=TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key: bytes = b"",
    ):
        self.local_id = local_id
        self.flags = flags
        self.send_id = send_id
        self.recv_id = recv_id
        self.alg = alg
        self.key = key

    @property
    def key(self) -> bytes:
        return bytes(self.keybuf[: self.keylen])

    @key.setter
    def key(self, val: bytes) -> bytes:
        if len(val) > TCP_AUTHOPT_MAXKEYLEN:
            raise ValueError(f"Max key length is {TCP_AUTHOPT_MAXKEYLEN}")
        self.keylen = len(val)
        self.keybuf = _keybuf.from_buffer_copy(val.ljust(TCP_AUTHOPT_MAXKEYLEN, b"\0"))
        return val

    @property
    def include_options(self) -> bool:
        return (self.flags & TCP_AUTHOPT_KEY_EXCLUDE_OPTS) == 0

    @include_options.setter
    def include_options(self, value) -> bool:
        if value:
            self.flags &= ~TCP_AUTHOPT_KEY_EXCLUDE_OPTS
        else:
            self.flags |= TCP_AUTHOPT_KEY_EXCLUDE_OPTS


def set_tcp_authopt_key(sock, key: tcp_authopt_key):
    return sock.setsockopt(socket.IPPROTO_TCP, TCP_AUTHOPT_KEY, bytes(key))


def del_tcp_authopt_key_by_id(sock, local_id: int):
    opt = tcp_authopt_key(local_id=local_id, flags=TCP_AUTHOPT_KEY_DEL)
    return sock.setsockopt(socket.IPPROTO_TCP, TCP_AUTHOPT_KEY, bytes(opt))
