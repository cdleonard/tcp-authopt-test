# SPDX-License-Identifier: GPL-2.0
"""Python wrapper around linux TCP_AUTHOPT ABI"""

import errno
import logging
import socket
import struct
import typing
from dataclasses import dataclass
from enum import IntEnum, IntFlag

from .flag_property import FlagProperty
from .sockaddr import (
    SockaddrConvertType,
    sockaddr_base,
    sockaddr_convert,
    sockaddr_storage,
    sockaddr_unpack,
)

logger = logging.getLogger(__name__)


def BIT(x):
    return 1 << x


TCP_AUTHOPT = 38
TCP_AUTHOPT_KEY = 39

TCP_AUTHOPT_MAXKEYLEN = 80


class TCP_AUTHOPT_FLAG(IntFlag):
    LOCK_KEYID = BIT(0)
    LOCK_RNEXTKEYID = BIT(1)
    REJECT_UNEXPECTED = BIT(2)


class TCP_AUTHOPT_KEY_FLAG(IntFlag):
    DEL = BIT(0)
    EXCLUDE_OPTS = BIT(1)
    BIND_ADDR = BIT(2)
    IFINDEX = BIT(3)
    NOSEND = BIT(4)
    NORECV = BIT(5)
    PREFIXLEN = BIT(6)


class TCP_AUTHOPT_ALG(IntEnum):
    HMAC_SHA_1_96 = 1
    AES_128_CMAC_96 = 2


@dataclass
class tcp_authopt:
    """Like linux struct tcp_authopt"""

    flags: int = 0
    send_keyid: int = 0
    send_rnextkeyid: int = 0
    recv_keyid: int = 0
    recv_rnextkeyid: int = 0
    sizeof = 8

    def pack(self) -> bytes:
        return struct.pack(
            "IBBBB",
            self.flags,
            self.send_keyid,
            self.send_rnextkeyid,
            self.recv_keyid,
            self.recv_rnextkeyid,
        )

    def __bytes__(self):
        return self.pack()

    @classmethod
    def unpack(cls, b: bytes):
        tup = struct.unpack("IBBBB", b)
        return cls(*tup)


def set_tcp_authopt(sock, opt: tcp_authopt):
    return sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT, bytes(opt))


def get_tcp_authopt(sock: socket.socket) -> tcp_authopt:
    b = sock.getsockopt(socket.SOL_TCP, TCP_AUTHOPT, tcp_authopt.sizeof)
    return tcp_authopt.unpack(b)


class tcp_authopt_key:
    """Like linux struct tcp_authopt_key

    :ivar auto_flags: If true(default) then set "binding" flags based on non-null values attributes.
    """

    KeyArgType = typing.Union[str, bytes]
    AddrArgType = typing.Union[None, str, bytes, SockaddrConvertType]
    send_id: int
    recv_id: int
    prefixlen: int

    def __init__(
        self,
        flags: TCP_AUTHOPT_KEY_FLAG = TCP_AUTHOPT_KEY_FLAG(0),
        send_id: int = 0,
        recv_id: int = 0,
        alg=TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
        key: KeyArgType = b"",
        addr: AddrArgType = None,
        auto_flags: bool = True,
        prefixlen: typing.Optional[int] = None,
        ifindex: typing.Optional[int] = None,
        include_options=None,
        nosend: bool = False,
        norecv: bool = False,
    ):
        self.flags = flags
        self.send_id = send_id
        self.recv_id = recv_id
        self.alg = alg
        self.key = key
        self.ifindex = ifindex
        self.addr = addr
        self.prefixlen = prefixlen
        self.auto_flags = auto_flags
        self.nosend = nosend
        self.norecv = norecv
        if include_options is not None:
            self.include_options = include_options

    def get_real_flags(self) -> TCP_AUTHOPT_KEY_FLAG:
        result = self.flags
        if self.auto_flags:
            if self.ifindex is not None:
                result |= TCP_AUTHOPT_KEY_FLAG.IFINDEX
            else:
                result &= ~TCP_AUTHOPT_KEY_FLAG.IFINDEX
            if self.addr is not None:
                result |= TCP_AUTHOPT_KEY_FLAG.BIND_ADDR
            else:
                result &= ~TCP_AUTHOPT_KEY_FLAG.BIND_ADDR
            if self.prefixlen is not None:
                result |= TCP_AUTHOPT_KEY_FLAG.PREFIXLEN
            else:
                result &= ~TCP_AUTHOPT_KEY_FLAG.PREFIXLEN
        return result

    def pack(self):
        if len(self.key) > TCP_AUTHOPT_MAXKEYLEN:
            raise ValueError(f"Max key length is {TCP_AUTHOPT_MAXKEYLEN}")
        data = struct.pack(
            "IBBBB80s",
            self.get_real_flags(),
            self.send_id,
            self.recv_id,
            self.alg,
            len(self.key),
            self.key,
        )
        data += bytes(self.addrbuf.ljust(sockaddr_storage.sizeof, b"\x00"))
        if self.ifindex is not None or self.prefixlen is not None:
            data += bytes(struct.pack("I", self.ifindex or 0))
        if self.prefixlen is not None:
            data += bytes(struct.pack("I", self.prefixlen))
        return data

    def __bytes__(self):
        return self.pack()

    @property
    def key(self) -> KeyArgType:
        return self._key

    @key.setter
    def key(self, val: KeyArgType) -> bytes:
        if isinstance(val, str):
            val = val.encode("utf-8")
        if len(val) > TCP_AUTHOPT_MAXKEYLEN:
            raise ValueError(f"Max key length is {TCP_AUTHOPT_MAXKEYLEN}")
        self._key = val
        return val

    @property
    def addr(self):
        if not self.addrbuf:
            return None
        else:
            return sockaddr_unpack(bytes(self.addrbuf))

    @addr.setter
    def addr(self, val: AddrArgType):
        if isinstance(val, bytes):
            if len(val) > sockaddr_storage.sizeof:
                raise ValueError(f"Must be up to {sockaddr_storage.sizeof}")
            self.addrbuf = val
        elif val is None:
            self.addrbuf = b""
        elif isinstance(val, sockaddr_base):
            self.addr = bytes(val)
        else:
            self.addr = sockaddr_convert(val)
        return self.addr

    include_options = FlagProperty("flags", TCP_AUTHOPT_KEY_FLAG.EXCLUDE_OPTS, rev=True)
    delete_flag = FlagProperty("flags", TCP_AUTHOPT_KEY_FLAG.DEL)
    nosend = FlagProperty("flags", TCP_AUTHOPT_KEY_FLAG.NOSEND)
    norecv = FlagProperty("flags", TCP_AUTHOPT_KEY_FLAG.NORECV)


def set_tcp_authopt_key(sock, keyopt: tcp_authopt_key):
    return sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT_KEY, bytes(keyopt))


def set_tcp_authopt_key_kwargs(sock, keyopt: tcp_authopt_key = None, **kw):
    if keyopt is None:
        keyopt = tcp_authopt_key()
    for k, v in kw.items():
        setattr(keyopt, k, v)
    return set_tcp_authopt_key(sock, keyopt)


def del_tcp_authopt_key(sock, key: tcp_authopt_key) -> bool:
    """Try to delete an authopt key

    :return: True if a key was deleted, False if it was not present
    """
    import copy

    key = copy.copy(key)
    key.delete_flag = True
    try:
        sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT_KEY, bytes(key))
        return True
    except OSError as e:
        if e.errno == errno.ENOENT:
            return False
        raise


def get_sysctl_tcp_authopt() -> typing.Optional[bool]:
    from pathlib import Path

    path = Path("/proc/sys/net/ipv4/tcp_authopt")
    if path.exists():
        return path.read_text().strip() != "0"
    else:
        return None


def enable_sysctl_tcp_authopt():
    from pathlib import Path

    path = Path("/proc/sys/net/ipv4/tcp_authopt")
    # Do nothing if absent
    if not path.exists():
        return
    try:
        if path.read_text().strip() == "0":
            path.write_text("1")
    except:
        raise Exception("Failed to enable /proc/sys/net/ipv4/tcp_authopt")


def has_tcp_authopt() -> bool:
    """Check is TCP_AUTHOPT is implemented by the OS

    Returns True if implemented but disabled by sysctl
    Returns False if disabled at compile time
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            optbuf = bytes(4)
            sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT, optbuf)
            return True
        except OSError as e:
            if e.errno == errno.ENOPROTOOPT:
                return False
            elif e.errno == errno.EPERM and get_sysctl_tcp_authopt() is False:
                return True
            else:
                raise
