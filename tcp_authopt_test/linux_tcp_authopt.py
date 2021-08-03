"""Python wrapper around linux TCP_AUTHOPT ABI"""

from ipaddress import IPv4Address, ip_address
import socket
import logging
from .sockaddr import sockaddr_in, sockaddr_storage, sockaddr_unpack
import typing
import ctypes
from ctypes import c_uint32, c_uint8, c_byte

logger = logging.getLogger(__name__)


def BIT(x):
    return 1 << x


TCP_AUTHOPT = 38
TCP_AUTHOPT_KEY = 39

TCP_AUTHOPT_MAXKEYLEN = 80

TCP_AUTHOPT_FLAG_LOCK_KEYID = BIT(0)
TCP_AUTHOPT_FLAG_LOCK_RNEXTKEYID = BIT(1)
TCP_AUTHOPT_FLAG_REJECT_UNEXPECTED = BIT(2)

TCP_AUTHOPT_KEY_DEL = BIT(0)
TCP_AUTHOPT_KEY_EXCLUDE_OPTS = BIT(1)
TCP_AUTHOPT_KEY_BIND_ADDR = BIT(2)

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
SIZEOF_SOCKADDR_STORAGE = 128
_addrbuf = c_byte * SIZEOF_SOCKADDR_STORAGE


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
        ("_pad", c_uint32),
        ("addrbuf", _addrbuf),
    ]

    def __init__(
        self,
        flags: int = 0,
        local_id: int = 0,
        send_id: int = 0,
        recv_id: int = 0,
        alg=TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key: bytes = b"",
        addr: bytes = b"",
    ):
        self.local_id = local_id
        self.flags = flags
        self.send_id = send_id
        self.recv_id = recv_id
        self.alg = alg
        self.key = key
        if addr:
            self.addr = addr

    @property
    def key(self) -> bytes:
        return bytes(self.keybuf[: self.keylen])

    @key.setter
    def key(self, val: typing.Union[bytes, str]) -> bytes:
        if len(val) > TCP_AUTHOPT_MAXKEYLEN:
            raise ValueError(f"Max key length is {TCP_AUTHOPT_MAXKEYLEN}")
        if isinstance(val, str):
            val = val.encode("utf-8")
        self.keylen = len(val)
        self.keybuf = _keybuf.from_buffer_copy(val.ljust(TCP_AUTHOPT_MAXKEYLEN, b"\0"))
        return val

    @property
    def addr(self):
        return sockaddr_unpack(bytes(self.addrbuf))

    @addr.setter
    def addr(self, val):
        if isinstance(val, bytes):
            if len(val) > SIZEOF_SOCKADDR_STORAGE:
                raise ValueError(f"Must be up to {SIZEOF_SOCKADDR_STORAGE}")
            self.addrbuf = _addrbuf.from_buffer_copy(
                val.ljust(SIZEOF_SOCKADDR_STORAGE, b"\0")
            )
        elif isinstance(val, str):
            self.addr = ip_address(val)
        elif isinstance(val, IPv4Address):
            self.addr = sockaddr_in(addr=val)
        elif isinstance(val, sockaddr_in) or isinstance(val, sockaddr_storage):
            self.addr = bytes(val)
        else:
            raise TypeError(f"Can't handle addr {val}")
        return self.addr

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
