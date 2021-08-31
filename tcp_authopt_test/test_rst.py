# SPDX-License-Identifier: GPL-2.0
from contextlib import ExitStack
import threading

from scapy.data import ETH_P_IP
from .netns_fixture import NamespaceFixture
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    AsyncSnifferContext,
    scapy_sniffer_stop,
    check_socket_echo,
    create_listen_socket,
    scapy_tcp_get_authopt_val,
    netns_context,
)
from .server import SimpleServerThread
from scapy.sessions import DefaultSession as SniffSession
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.config import conf as scapy_conf
from . import linux_tcp_authopt
from .linux_tcp_authopt import tcp_authopt_key, set_tcp_authopt_key
import socket
import logging
import pytest


logger = logging.getLogger(__name__)


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
    with netns_context(ns):
        return scapy_conf.L2socket(**kw)


def create_capture_socket(ns: str = "", **kw):
    """Create a scapy L2listen socket inside a namespace"""
    with netns_context(ns):
        return scapy_conf.L2listen(**kw)


def show_tcp_authopt_packet(
    p: Packet, include_ethernet=False, include_seq=False
) -> str:
    """Format a TCP packet in a way that is useful for TCP-AO testing"""
    if not TCP in p:
        return p.summary()
    result = p.sprintf(r"%IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport% Flags %TCP.flags%")
    if include_ethernet:
        result = (
            p.sprintf(r"%Ether.src% > %Ether.dst% ethertype %Ether.type% ") + result
        )
    if include_seq:
        result += p.sprintf(r" seq %TCP.seq% ack %TCP.ack%")
    authopt = scapy_tcp_get_authopt_val(p[TCP])
    if authopt:
        result += f" AO keyid={authopt.keyid} rnextkeyid={authopt.rnextkeyid} mac={authopt.mac.hex()}"
    else:
        result += " AO missing"
    return result


class TCPSeqSniffSession(SniffSession):
    """Sniff seq/ack numbers so that we can inject an RST"""

    seq: int = None
    ack: int = None

    def __init__(self, server_port=None, match_count_limit=2, **kw):
        super().__init__(**kw)
        self.server_port = server_port
        self.match_count = 0
        self.match_count_limit = match_count_limit
        self.match_count_event = threading.Event()

    def on_packet_received(self, p):
        super().on_packet_received(p)
        if not p or not TCP in p:
            return
        th = p[TCP]
        if self.server_port is None or th.sport == self.server_port:
            self.seq = th.seq
            self.ack = th.ack
            self.match_count += 1
            if self.match_count >= self.match_count_limit:
                self.match_count_event.set()

    def wait_match_count(self, timeout=None):
        self.match_count_event.wait(timeout)
        if not self.match_count_event.is_set():
            raise TimeoutError(f"Timed out timeout={timeout!r}")


@pytest.mark.parametrize(
    "address_family,signed",
    [(socket.AF_INET, True), (socket.AF_INET, False)],
)
def test_rst(exit_stack: ExitStack, address_family, signed: bool):
    """Check that an unsigned RST breaks a normal connection but not one protected by TCP-AO"""

    if signed and not linux_tcp_authopt.has_tcp_authopt():
        pytest.skip("need TCP_AUTHOPT")

    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = nsfixture.get_addr(address_family, 1)
    client_addr = nsfixture.get_addr(address_family, 2)
    server_port = DEFAULT_TCP_SERVER_PORT

    listen_socket = create_listen_socket(
        ns=nsfixture.ns1_name,
        family=address_family,
        bind_addr=server_addr,
    )
    exit_stack.enter_context(listen_socket)
    client_socket = create_client_socket(
        ns=nsfixture.ns2_name,
        family=address_family,
        bind_addr=client_addr,
    )
    exit_stack.enter_context(client_socket)
    server_thread = SimpleServerThread(listen_socket, mode="echo")
    exit_stack.enter_context(server_thread)

    if signed:
        key = tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
            key="hello",
        )
        set_tcp_authopt_key(listen_socket, key)
        set_tcp_authopt_key(client_socket, key)

    capture_filter = f"tcp port {server_port}"
    capture_socket = create_capture_socket(
        ns=nsfixture.ns1_name, iface="veth0", filter=capture_filter
    )
    exit_stack.enter_context(capture_socket)

    sniffer_session = TCPSeqSniffSession(server_port=server_port)
    sniffer = AsyncSnifferContext(opened_socket=capture_socket, session=sniffer_session)
    exit_stack.enter_context(sniffer)

    client_l2socket = create_l2socket(ns=nsfixture.ns2_name, iface="veth0")
    exit_stack.enter_context(client_l2socket)

    # connect
    client_socket.connect((str(server_addr), server_port))
    check_socket_echo(client_socket, 1000)
    (_, client_port) = client_socket.getsockname()

    try:
        ethhdr = Ether(type=ETH_P_IP, src=nsfixture.mac2, dst=nsfixture.mac1)
        iphdr = IP(src=str(client_addr), dst=str(server_addr))
        tcphdr = TCP(sport=client_port, dport=server_port)
        tcphdr.flags.R = True
        tcphdr.flags.S = False
        tcphdr.seq = sniffer_session.ack
        tcphdr.ack = sniffer_session.seq
        sniffer_session.wait_match_count(timeout=3.0)
        client_l2socket.send(ethhdr / iphdr / tcphdr)

        if signed:
            check_socket_echo(client_socket)
        else:
            with pytest.raises(ConnectionResetError):
                check_socket_echo(client_socket)
    finally:
        scapy_sniffer_stop(sniffer)

        def fmt(p):
            return show_tcp_authopt_packet(p, include_ethernet=True, include_seq=True)

        logger.info("sniffed:\n%s", "\n".join(map(fmt, sniffer.results)))
