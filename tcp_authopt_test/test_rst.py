# SPDX-License-Identifier: GPL-2.0
import logging
import socket
from contextlib import ExitStack

import pytest
from scapy.config import conf as scapy_conf
from scapy.data import ETH_P_IP
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from . import linux_tcp_authopt
from .full_tcp_sniff_session import FullTCPSniffSession
from .linux_tcp_authopt import set_tcp_authopt_key, tcp_authopt_key
from .netns_fixture import NamespaceFixture
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    AsyncSnifferContext,
    check_socket_echo,
    create_listen_socket,
    netns_context,
    scapy_sniffer_stop,
    scapy_tcp_get_authopt_val,
)
from .validator import TcpAuthValidator, TcpAuthValidatorKey

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


def socket_set_linger(sock, onoff, value):
    import struct

    sock.setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", int(onoff), int(value))
    )


def format_tcp_authopt_packet(
    p: Packet, include_ethernet=False, include_seq=False
) -> str:
    """Format a TCP packet in a way that is useful for TCP-AO testing"""
    if not TCP in p:
        return p.summary()
    result = p.sprintf(r"%IP.src%:%TCP.sport% > %IP.dst%:%TCP.dport%")
    result += p.sprintf(r" Flags %-2s,TCP.flags%")
    if include_ethernet:
        result = p.sprintf(r"ethertype %Ether.type% ") + result
        result = p.sprintf(r"%Ether.src% > %Ether.dst% ") + result
    if include_seq:
        result += p.sprintf(r" seq %TCP.seq% ack %TCP.ack%")
        result += f" len {len(p[TCP].payload)}"
    authopt = scapy_tcp_get_authopt_val(p[TCP])
    if authopt:
        result += f" AO keyid={authopt.keyid} rnextkeyid={authopt.rnextkeyid} mac={authopt.mac.hex()}"
    else:
        result += " AO missing"
    return result


def log_tcp_authopt_packet(p):
    logger.info("sniff %s", format_tcp_authopt_packet(p, include_seq=True))


class Context:
    """Test context to avoid repetition

    Includes:
    * pair of network namespaces
    * one listen socket
    * server thread with echo protocol
    * one client socket
    * one async sniffer on the server interface
    * l2socket allowing packet injection from client
    """

    def __init__(
        self,
        address_family=socket.AF_INET,
        sniffer_session=None,
        sniffer_kwargs=None,
        tcp_authopt_key: tcp_authopt_key = None,
    ):
        self.address_family = address_family
        self.server_port = DEFAULT_TCP_SERVER_PORT
        self.client_port = 27972
        self.sniffer_session = sniffer_session
        if sniffer_kwargs is None:
            sniffer_kwargs = {}
        self.sniffer_kwargs = sniffer_kwargs
        self.tcp_authopt_key = tcp_authopt_key

    def __enter__(self):
        if self.tcp_authopt_key and not linux_tcp_authopt.has_tcp_authopt:
            pytest.skip("Need TCP_AUTHOPT")

        self.exit_stack = ExitStack()
        self.exit_stack.__enter__()

        self.nsfixture = self.exit_stack.enter_context(NamespaceFixture())
        self.server_addr = self.nsfixture.get_addr(self.address_family, 1)
        self.client_addr = self.nsfixture.get_addr(self.address_family, 2)

        self.listen_socket = create_listen_socket(
            ns=self.nsfixture.ns1_name,
            family=self.address_family,
            bind_addr=self.server_addr,
            bind_port=self.server_port,
        )
        self.exit_stack.enter_context(self.listen_socket)
        self.client_socket = create_client_socket(
            ns=self.nsfixture.ns2_name,
            family=self.address_family,
            bind_addr=self.client_addr,
            bind_port=self.client_port,
        )
        self.exit_stack.enter_context(self.client_socket)
        self.server_thread = SimpleServerThread(self.listen_socket, mode="echo")
        self.exit_stack.enter_context(self.server_thread)

        if self.tcp_authopt_key:
            set_tcp_authopt_key(self.listen_socket, self.tcp_authopt_key)
            set_tcp_authopt_key(self.client_socket, self.tcp_authopt_key)

        capture_filter = f"tcp port {self.server_port}"
        self.capture_socket = create_capture_socket(
            ns=self.nsfixture.ns1_name, iface="veth0", filter=capture_filter
        )
        self.exit_stack.enter_context(self.capture_socket)

        self.sniffer = AsyncSnifferContext(
            opened_socket=self.capture_socket,
            session=self.sniffer_session,
            prn=log_tcp_authopt_packet,
            **self.sniffer_kwargs,
        )
        self.exit_stack.enter_context(self.sniffer)

        self.client_l2socket = create_l2socket(
            ns=self.nsfixture.ns2_name, iface="veth0"
        )
        self.exit_stack.enter_context(self.client_l2socket)
        self.server_l2socket = create_l2socket(
            ns=self.nsfixture.ns1_name, iface="veth0"
        )
        self.exit_stack.enter_context(self.server_l2socket)

    def __exit__(self, *args):
        self.exit_stack.__exit__(*args)

    def create_client2server_packet(self) -> Packet:
        return (
            Ether(type=ETH_P_IP, src=self.nsfixture.mac2, dst=self.nsfixture.mac1)
            / IP(src=str(self.client_addr), dst=str(self.server_addr))
            / TCP(sport=self.client_port, dport=self.server_port)
        )

    def create_server2client_packet(self) -> Packet:
        return (
            Ether(type=ETH_P_IP, src=self.nsfixture.mac1, dst=self.nsfixture.mac2)
            / IP(src=str(self.server_addr), dst=str(self.client_addr))
            / TCP(sport=self.server_port, dport=self.client_port)
        )


DEFAULT_TCP_AUTHOPT_KEY = tcp_authopt_key(
    alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
    key=b"hello",
)


@pytest.mark.parametrize(
    "address_family,signed",
    [(socket.AF_INET, True), (socket.AF_INET, False)],
)
def test_rst(exit_stack: ExitStack, address_family, signed: bool):
    """Check that an unsigned RST breaks a normal connection but not one protected by TCP-AO"""

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = Context(sniffer_session=sniffer_session)
    if signed:
        context.tcp_authopt_key = DEFAULT_TCP_AUTHOPT_KEY
    exit_stack.enter_context(context)

    # connect
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)

    p = context.create_client2server_packet()
    p[TCP].flags = "R"
    p[TCP].seq = sniffer_session.client_isn + 1001
    p[TCP].ack = sniffer_session.server_isn + 1001
    context.client_l2socket.send(p)

    if signed:
        # When protected by TCP-AO unsigned RSTs are ignored.
        check_socket_echo(context.client_socket)
    else:
        # By default an RST that guesses seq can kill the connection.
        with pytest.raises(ConnectionResetError):
            check_socket_echo(context.client_socket)


def test_rst_linger(exit_stack: ExitStack):
    """Test RST sent deliberately via SO_LINGER is valid"""
    context = Context(sniffer_kwargs=dict(count=8))
    exit_stack.enter_context(context)

    key = tcp_authopt_key(
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key=f"hello",
    )
    set_tcp_authopt_key(context.listen_socket, key)
    set_tcp_authopt_key(context.client_socket, key)

    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)
    socket_set_linger(context.client_socket, 1, 0)
    context.client_socket.close()

    context.sniffer.join(timeout=3)

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()

    def is_tcp_rst(p):
        return TCP in p and p[TCP].flags.R

    assert any(is_tcp_rst(p) for p in context.sniffer.results)


@pytest.mark.parametrize("address_family", (socket.AF_INET, socket.AF_INET6))
@pytest.mark.parametrize("index", range(10))
def test_short_conn(exit_stack: ExitStack, address_family, index):
    """Test TWSK sends signed RST"""

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = Context(address_family=address_family, sniffer_session=sniffer_session)
    exit_stack.enter_context(context)

    key = tcp_authopt_key(
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key=f"hello",
    )
    set_tcp_authopt_key(context.listen_socket, key)
    set_tcp_authopt_key(context.client_socket, key)

    # Connect and close nicely
    context.client_socket.connect((str(context.server_addr), context.server_port))
    context.client_socket.close()

    sniffer_session.wait_close()
    scapy_sniffer_stop(context.sniffer)

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()
