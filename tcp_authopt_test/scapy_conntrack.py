# SPDX-License-Identifier: GPL-2.0
"""Identify TCP connections inside a capture and collect per-connection information"""
import typing
from dataclasses import dataclass

from scapy.layers.inet import TCP
from scapy.packet import Packet

from .scapy_utils import (
    IPvXAddress,
    get_packet_ipvx_dst,
    get_packet_ipvx_src,
    tcp_seq_wrap,
)
from .sne_alg import SequenceNumberExtenderLinux


@dataclass(frozen=True)
class TCPConnectionKey:
    """TCP connection identification key: standard 4-tuple"""

    saddr: typing.Optional[IPvXAddress] = None
    daddr: typing.Optional[IPvXAddress] = None
    sport: int = 0
    dport: int = 0

    def rev(self) -> "TCPConnectionKey":
        return TCPConnectionKey(self.daddr, self.saddr, self.dport, self.sport)


def get_packet_tcp_connection_key(p: Packet) -> TCPConnectionKey:
    th = p[TCP]
    return TCPConnectionKey(
        get_packet_ipvx_src(p), get_packet_ipvx_dst(p), th.sport, th.dport
    )


class TCPConnectionInfo:
    saddr: typing.Optional[IPvXAddress] = None
    daddr: typing.Optional[IPvXAddress] = None
    sport: int = 0
    dport: int = 0
    sisn: typing.Optional[int] = None
    disn: typing.Optional[int] = None
    rcv_sne: SequenceNumberExtenderLinux
    snd_sne: SequenceNumberExtenderLinux

    found_syn = False
    found_synack = False

    found_send_fin = False
    found_send_finack = False
    found_recv_fin = False
    found_recv_finack = False

    def __init__(self):
        self.rcv_sne = SequenceNumberExtenderLinux()
        self.snd_sne = SequenceNumberExtenderLinux()

    def get_key(self):
        return TCPConnectionKey(self.saddr, self.daddr, self.sport, self.dport)

    @classmethod
    def from_key(cls, key: TCPConnectionKey) -> "TCPConnectionInfo":
        obj = cls()
        obj.saddr = key.saddr
        obj.daddr = key.daddr
        obj.sport = key.sport
        obj.dport = key.dport
        return obj

    def handle_send(self, p: Packet):
        th = p[TCP]
        if self.get_key() != get_packet_tcp_connection_key(p):
            raise ValueError("Packet not for this connection")

        if th.flags.S and not th.flags.A:
            assert th.ack == 0
            self.found_syn = True
            self.sisn = th.seq
            self.snd_sne.reset(th.seq)
        elif th.flags.S and th.flags.A:
            self.found_synack = True
            self.sisn = th.seq
            self.snd_sne.reset(th.seq)
            assert self.disn == tcp_seq_wrap(th.ack - 1)

        # Should track seq numbers instead
        if th.flags.F:
            self.found_send_fin = True
        if th.flags.A and self.found_recv_fin:
            self.found_send_finack = True

        # Should only take valid packets into account
        self.snd_sne.calc(th.seq)

    def handle_recv(self, p: Packet):
        th = p[TCP]
        if self.get_key().rev() != get_packet_tcp_connection_key(p):
            raise ValueError("Packet not for this connection")

        if th.flags.S and not th.flags.A:
            assert th.ack == 0
            self.found_syn = True
            self.disn = th.seq
            self.rcv_sne.reset(th.seq)
        elif th.flags.S and th.flags.A:
            self.found_synack = True
            self.disn = th.seq
            self.rcv_sne.reset(th.seq)
            assert self.sisn == tcp_seq_wrap(th.ack - 1)

        # Should track seq numbers instead
        if th.flags.F:
            self.found_recv_fin = True
        if th.flags.A and self.found_send_fin:
            self.found_recv_finack = True

        # Should only take valid packets into account
        self.rcv_sne.calc(th.seq)


class TCPConnectionTracker:
    table: typing.Dict[TCPConnectionKey, TCPConnectionInfo]

    def __init__(self):
        self.table = {}

    def reset(self):
        """Forget known connections"""
        self.table = {}

    def get_or_create(self, key: TCPConnectionKey) -> TCPConnectionInfo:
        info = self.table.get(key, None)
        if info is None:
            info = TCPConnectionInfo.from_key(key)
            self.table[key] = info
        return info

    def get(self, key: TCPConnectionKey) -> typing.Optional[TCPConnectionInfo]:
        return self.table.get(key, None)

    def handle_packet(self, p: Packet):
        if not p or not TCP in p:
            return
        key = get_packet_tcp_connection_key(p)
        info = self.get_or_create(key)
        info.handle_send(p)
        rkey = key.rev()
        rinfo = self.get_or_create(rkey)
        rinfo.handle_recv(p)

    def iter_match(self, saddr=None, daddr=None, sport=None, dport=None):
        def attr_optional_match(obj, name, val) -> bool:
            if val is None:
                return True
            else:
                return getattr(obj, name) == val

        for key, info in self.table.items():
            if (
                attr_optional_match(key, "saddr", saddr)
                and attr_optional_match(key, "daddr", daddr)
                and attr_optional_match(key, "sport", sport)
                and attr_optional_match(key, "dport", dport)
            ):
                yield info

    def match_one(
        self, saddr=None, daddr=None, sport=None, dport=None
    ) -> typing.Optional[TCPConnectionInfo]:
        res = list(self.iter_match(saddr, daddr, sport, dport))
        if len(res) == 1:
            return res[0]
        elif len(res) == 0:
            return None
        else:
            raise ValueError("Multiple connection matches")
