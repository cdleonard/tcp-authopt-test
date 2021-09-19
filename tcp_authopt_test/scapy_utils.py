import typing
import threading
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

from scapy.config import conf as scapy_conf
from scapy.sendrecv import AsyncSniffer

from .utils import netns_context

# TCPOPT numbers are apparently not available in scapy
TCPOPT_MD5SIG = 19
TCPOPT_AUTHOPT = 29

# Easy generic handling of IPv4/IPv6Address
IPvXAddress = typing.Union[IPv4Address, IPv6Address]


def tcp_seq_wrap(seq):
    return seq & 0xFFFFFFFF


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


def create_l2socket(ns: str = "", **kw):
    """Create a scapy L2socket inside a namespace"""

    with netns_context(ns):
        return scapy_conf.L2socket(**kw)


def create_capture_socket(ns: str = "", **kw):
    """Create a scapy L2listen socket inside a namespace"""
    from scapy.config import conf as scapy_conf

    with netns_context(ns):
        return scapy_conf.L2listen(**kw)


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
