# SPDX-License-Identifier: GPL-2.0
import json
import random
import subprocess
import threading
import typing
import socket
from ipaddress import IPv4Address, IPv6Address
from dataclasses import dataclass
from contextlib import nullcontext

from nsenter import Namespace
from scapy.sendrecv import AsyncSniffer

# TCPOPT numbers are apparently not available in scapy
TCPOPT_MD5SIG = 19
TCPOPT_AUTHOPT = 29

# Easy generic handling of IPv4/IPv6Address
IPvXAddress = typing.Union[IPv4Address, IPv6Address]

# TCP port does not impact Authentication Option so define a single default
DEFAULT_TCP_SERVER_PORT = 17971


def recvall(sock, todo):
    """Receive exactly todo bytes unless EOF"""
    data = bytes()
    while True:
        chunk = sock.recv(todo)
        if not len(chunk):
            return data
        data += chunk
        todo -= len(chunk)
        if todo == 0:
            return data
        assert todo > 0


def randbytes(count) -> bytes:
    """Return a random byte array"""
    return bytes([random.randint(0, 255) for index in range(count)])


def check_socket_echo(sock: socket.socket, size=1000):
    """Send random bytes and check they are received

    The default size is equal to `SimpleServerThread.DEFAULT_BUFSIZE` which
    means that a single pair of packets will be sent at the TCP level.
    """
    send_buf = randbytes(size)
    sock.sendall(send_buf)
    recv_buf = recvall(sock, size)
    assert send_buf == recv_buf


def nstat_json(command_prefix: str = ""):
    """Parse nstat output into a python dict"""
    runres = subprocess.run(
        f"{command_prefix}nstat -a --zeros --json",
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )
    return json.loads(runres.stdout)["kernel"]


def netns_context(ns: str = ""):
    """Create context manager for a certain optional netns

    If the ns argument is empty then just return a `nullcontext`
    """
    if ns:
        return Namespace("/var/run/netns/" + ns, "net")
    else:
        return nullcontext()


def create_listen_socket(
    ns: str = "",
    family=socket.AF_INET,
    reuseaddr=True,
    listen_depth=10,
    bind_addr="",
    bind_port=DEFAULT_TCP_SERVER_PORT,
):
    with netns_context(ns):
        listen_socket = socket.socket(family, socket.SOCK_STREAM)
    if reuseaddr:
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((str(bind_addr), bind_port))
    listen_socket.listen(listen_depth)
    return listen_socket


def create_client_socket(
    ns: str = "", family=socket.AF_INET, bind_addr="", bind_port=0, timeout=1.0
):
    with netns_context(ns):
        client_socket = socket.socket(family, socket.SOCK_STREAM)
    if bind_addr or bind_port:
        client_socket.bind((str(bind_addr), bind_port))
    if timeout is not None:
        client_socket.settimeout(timeout)
    return client_socket


def create_l2socket(ns: str = "", **kw):
    """Create a scapy L2socket inside a namespace"""
    from scapy.config import conf as scapy_conf

    with netns_context(ns):
        return scapy_conf.L2socket(**kw)


def create_capture_socket(ns: str = "", **kw):
    """Create a scapy L2listen socket inside a namespace"""
    from scapy.config import conf as scapy_conf

    with netns_context(ns):
        return scapy_conf.L2listen(**kw)


def socket_set_linger(sock, onoff, value):
    import struct

    sock.setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", int(onoff), int(value))
    )


@dataclass
class tcphdr_authopt:
    """Representation of a TCP auth option as it appears in a TCP packet"""

    keyid: int
    rnextkeyid: int
    mac: bytes

    @classmethod
    def unpack(cls, buf) -> "tcphdr_authopt":
        return cls(buf[0], buf[1], buf[2:])

    def __repr__(self):
        return f"tcphdr_authopt({self.keyid}, {self.rnextkeyid}, bytes.fromhex({self.mac.hex(' ')!r})"


def tcp_seq_wrap(seq):
    return seq & 0xFFFFFFFF


def scapy_tcp_get_authopt_val(tcp) -> typing.Optional[tcphdr_authopt]:
    for optnum, optval in tcp.options:
        if optnum == TCPOPT_AUTHOPT:
            return tcphdr_authopt.unpack(optval)
    return None


def scapy_tcp_get_md5_sig(tcp) -> typing.Optional[bytes]:
    """Return the MD5 signature (as bytes) or None"""
    for optnum, optval in tcp.options:
        if optnum == TCPOPT_MD5SIG:
            return optval
    return None


def scapy_sniffer_start_block(sniffer: AsyncSniffer, timeout=1):
    """Like AsyncSniffer.start except block until sniffing starts

    This ensures no lost packets and no delays
    """
    if sniffer.kwargs.get("started_callback"):
        raise ValueError("sniffer must not already have a started_callback")

    e = threading.Event()
    sniffer.kwargs["started_callback"] = e.set
    sniffer.start()
    e.wait(timeout=timeout)
    if not e.is_set():
        raise TimeoutError("Timed out waiting for sniffer to start")


def scapy_sniffer_stop(sniffer: AsyncSniffer):
    """Like AsyncSniffer.stop except no error is raising if not running"""
    if sniffer is not None and sniffer.running:
        sniffer.stop()


class AsyncSnifferContext(AsyncSniffer):
    def __enter__(self):
        scapy_sniffer_start_block(self)
        return self

    def __exit__(self, *a):
        scapy_sniffer_stop(self)
