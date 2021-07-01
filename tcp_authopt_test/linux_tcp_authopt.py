"""Python wrapper around linux TCP_MD5SIG ioctls"""

import socket
import struct
from dataclasses import dataclass
from .sockaddr import sockaddr_unpack


TCP_AUTHOPT = 38
TCP_AUTHOPT_KEY = 39

TCP_AUTHOPT_MAXKEYLEN = 80
TCP_AUTHOPT_KDF_HMAC_SHA1 = 1
TCP_AUTHOPT_KDF_AES_128_CMAC = 2
TCP_AUTHOPT_MAC_HMAC_SHA_1_96 = 1
TCP_AUTHOPT_MAC_AES_128_CMAC_96 = 2


@dataclass
class tcp_authopt:
    """Like linux struct tcp_authopt"""

    flags: int = 0
    send_local_id: int = 0

    struct_format = "II"
    sizeof = struct.calcsize(struct_format)

    def pack(self) -> bytes:
        return struct.pack(self.struct_format, self.flags, self.send_local_id)

    @classmethod
    def unpack(cls, buffer: bytes) -> "tcp_authopt":
        args = struct.unpack(cls.struct_format, buffer)
        return cls(*args)


def set_tcp_authopt(sock, opt: tcp_authopt):
    return sock.setsockopt(socket.IPPROTO_TCP, TCP_AUTHOPT, opt.pack())


@dataclass
class tcp_authopt_key:
    """Like linux struct tcp_authopt_key"""

    local_id: int
    key: bytes
    flags: int = 0
    send_id: int = 0
    recv_id: int = 0
    kdf: int = TCP_AUTHOPT_KDF_HMAC_SHA1
    mac: int = TCP_AUTHOPT_MAC_HMAC_SHA_1_96

    struct_format = "IIBBBBHxx80s"
    sizeof = struct.calcsize(struct_format)

    def pack(self) -> bytes:
        return struct.pack(
            self.struct_format,
            self.flags,
            self.local_id,
            self.send_id,
            self.recv_id,
            self.kdf,
            self.mac,
            len(self.key),
            self.key,
        )

    @classmethod
    def unpack(cls, buffer: bytes) -> "tcp_authopt_key":
        flags, local_id, send_id, recv_id, kdf, mac, keylen, key = struct.unpack(
            cls.struct_format, buffer
        )
        key = key[:keylen]
        return cls(
            flags, local_id, send_id=send_id, recv_id=recv_id, kdf=kdf, mac=mac, key=key
        )


def set_tcp_authopt_key(sock, key: tcp_authopt_key):
    return sock.setsockopt(socket.IPPROTO_TCP, TCP_AUTHOPT_KEY, key.pack())
