# SPDX-License-Identifier: GPL-2.0
from contextlib import ExitStack
import threading
import time
import subprocess

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
        self, address_family=socket.AF_INET, sniffer_session=None, sniffer_kwargs=None
    ):
        self.address_family = address_family
        self.server_port = DEFAULT_TCP_SERVER_PORT
        self.client_port = 27972
        self.sniffer_session = sniffer_session
        if sniffer_kwargs is None:
            sniffer_kwargs = {}
        self.sniffer_kwargs = sniffer_kwargs

    def __enter__(self):
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


@pytest.mark.parametrize(
    "address_family,signed",
    [(socket.AF_INET, True), (socket.AF_INET, False)],
)
def test_rst(exit_stack: ExitStack, address_family, signed: bool):
    """Check that an unsigned RST breaks a normal connection but not one protected by TCP-AO"""

    if signed and not linux_tcp_authopt.has_tcp_authopt():
        pytest.skip("need TCP_AUTHOPT")

    sniffer_session = TCPSeqSniffSession(server_port=DEFAULT_TCP_SERVER_PORT)
    context = Context(sniffer_session=sniffer_session)
    exit_stack.enter_context(context)

    if signed:
        key = tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
            key="hello",
        )
        set_tcp_authopt_key(context.listen_socket, key)
        set_tcp_authopt_key(context.client_socket, key)

    # connect
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)
    sniffer_session.wait_match_count(timeout=1.0)

    p = context.create_client2server_packet()
    p[TCP].flags.R = True
    p[TCP].flags.S = False
    p[TCP].seq = sniffer_session.ack
    p[TCP].ack = sniffer_session.seq
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

    from .validator import TcpAuthValidator
    from .validator import TcpAuthValidatorKey

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    assert not val.any_incomplete
    assert not val.any_unsigned
    assert not val.any_fail

    def is_tcp_rst(p):
        return TCP in p and p[TCP].flags.R

    assert any(is_tcp_rst(p) for p in context.sniffer.results)


@pytest.mark.xfail(reason="timewait broken")
def test_twsk_rst(exit_stack: ExitStack):
    """Test TWSK sends signed RST"""

    sniffer_session = TCPSeqSniffSession()
    context = Context(sniffer_session=sniffer_session)
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
    time.sleep(1)

    # Assert TIMEWAIT on client side only
    def runss(netns):
        cmd = f"ip netns exec {netns} ss -ntaH"
        return subprocess.check_output(cmd, text=True, shell=True)

    server_ss_output = runss(context.nsfixture.ns1_name)
    client_ss_output = runss(context.nsfixture.ns2_name)
    assert "WAIT" not in server_ss_output
    assert "WAIT" in client_ss_output
    logger.info("server ss:\n%s", server_ss_output)
    logger.info("client ss:\n%s", client_ss_output)

    p = context.create_server2client_packet()
    p[TCP].seq = sniffer_session.seq
    p[TCP].ack = sniffer_session.ack
    p[TCP].flags = "A"
    p = p / "AAAA"

    context.server_l2socket.send(p)
    time.sleep(1)

    scapy_sniffer_stop(context.sniffer)

    from .validator import TcpAuthValidator
    from .validator import TcpAuthValidatorKey

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    assert not val.any_incomplete
    assert not val.any_unsigned
    assert not val.any_fail


@pytest.mark.parametrize("index", range(10))
def test_short_conn(exit_stack: ExitStack, index):
    """Test TWSK sends signed RST"""

    context = Context()
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

    scapy_sniffer_stop(context.sniffer)

    from .validator import TcpAuthValidator
    from .validator import TcpAuthValidatorKey

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    assert not val.any_incomplete
    assert not val.any_fail
    assert not val.any_unsigned
