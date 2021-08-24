import logging
import os
import socket
import typing
from contextlib import ExitStack, contextmanager
from ipaddress import IPv4Address, IPv6Address
from nsenter import Namespace

import pytest
from scapy.layers.inet import TCP
import scapy.sessions

from . import tcp_authopt_alg
from . import linux_tcp_authopt
from .linux_tcp_authopt import (
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .validator import TcpAuthValidator, TcpAuthValidatorKey
from .netns_fixture import NamespaceFixture
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    AsyncSnifferContext,
    SimpleWaitEvent,
    check_socket_echo,
    create_listen_socket,
    netns_context,
    nstat_json,
    scapy_sniffer_stop,
)

logger = logging.getLogger(__name__)


def can_capture():
    # This is too restrictive:
    return os.geteuid() == 0


skipif_cant_capture = pytest.mark.skipif(
    not can_capture(), reason="run as root to capture packets"
)


def test_nonauth_connect(exit_stack):
    listen_socket = exit_stack.enter_context(create_listen_socket())
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
    check_socket_echo(client_socket)


def test_multi_nonauth_connect():
    """Test that the client/server infrastructure does not leak or hang"""
    for i in range(10):
        with ExitStack() as exit_stack:
            logger.info("ITER %d", i)
            test_nonauth_connect(exit_stack)


class CompleteTCPCaptureSniffSession(scapy.sessions.DefaultSession):
    """Smart scapy sniff session

    Allow waiting to capture FIN
    """

    found_syn = False
    found_synack = False
    found_fin = False
    found_client_fin = False
    found_server_fin = False

    def __init__(self, server_port=None, **kw):
        super().__init__(**kw)
        self.server_port = server_port
        self._close_event = SimpleWaitEvent()

    def on_packet_received(self, p):
        super().on_packet_received(p)
        if not p or not TCP in p:
            return
        th = p[TCP]
        # logger.debug("sport=%d dport=%d flags=%s", th.sport, th.dport, th.flags)
        if th.flags.S and not th.flags.A:
            if th.dport == self.server_port or self.server_port is None:
                self.found_syn = True
        if th.flags.S and th.flags.A:
            if th.sport == self.server_port or self.server_port is None:
                self.found_synack = True
        if th.flags.F:
            if self.server_port is None:
                self.found_fin = True
                self._close_event.set()
            elif self.server_port == th.dport:
                self.found_client_fin = True
                self.found_fin = True
                if self.found_server_fin and self.found_client_fin:
                    self._close_event.set()
            elif self.server_port == th.sport:
                self.found_server_fin = True
                self.found_fin = True
                if self.found_server_fin and self.found_client_fin:
                    self._close_event.set()

    def wait_close(self, timeout=10):
        self._close_event.wait(timeout=timeout)


@skipif_cant_capture
def test_complete_sniff(exit_stack: ExitStack):
    """Test that the whole TCP conversation is sniffed by scapy"""
    session = CompleteTCPCaptureSniffSession(server_port=DEFAULT_TCP_SERVER_PORT)
    sniffer = exit_stack.enter_context(
        AsyncSnifferContext(
            filter=f"tcp port {DEFAULT_TCP_SERVER_PORT}", iface="lo", session=session
        )
    )

    listen_socket = create_listen_socket()
    listen_socket = exit_stack.enter_context(listen_socket)
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
    check_socket_echo(client_socket)
    client_socket.close()
    session.wait_close()
    sniffer.stop()

    found_syn = False
    found_synack = False
    found_client_fin = False
    found_server_fin = False
    for p in sniffer.results:
        th = p[TCP]
        logger.info("sport=%d dport=%d flags=%s", th.sport, th.dport, th.flags)
        if p[TCP].flags.S and not p[TCP].flags.A:
            assert p[TCP].dport == DEFAULT_TCP_SERVER_PORT
            found_syn = True
        if p[TCP].flags.S and p[TCP].flags.A:
            assert p[TCP].sport == DEFAULT_TCP_SERVER_PORT
            found_synack = True
        if p[TCP].flags.F:
            if p[TCP].dport == DEFAULT_TCP_SERVER_PORT:
                found_client_fin = True
            else:
                found_server_fin = True
    assert found_syn and found_synack and found_client_fin and found_server_fin


class MainTestBase:
    """Can be parametrized by inheritance"""

    master_key = b"testvector"
    address_family = None
    alg_name = "HMAC-SHA-1-96"

    def get_alg(self):
        return tcp_authopt_alg.get_alg(self.alg_name)

    def get_alg_id(self) -> int:
        if self.alg_name == "HMAC-SHA-1-96":
            return linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96
        elif self.alg_name == "AES-128-CMAC-96":
            return linux_tcp_authopt.TCP_AUTHOPT_ALG_AES_128_CMAC_96
        else:
            raise ValueError()

    @skipif_cant_capture
    def test_authopt_connect_sniff(self, exit_stack: ExitStack):
        session = CompleteTCPCaptureSniffSession(server_port=DEFAULT_TCP_SERVER_PORT)
        sniffer = exit_stack.enter_context(
            AsyncSnifferContext(
                filter=f"tcp port {DEFAULT_TCP_SERVER_PORT}",
                iface="lo",
                session=session,
            )
        )

        listen_socket = create_listen_socket(family=self.address_family)
        listen_socket = exit_stack.enter_context(listen_socket)
        exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

        client_socket = socket.socket(self.address_family, socket.SOCK_STREAM)
        client_socket = exit_stack.push(client_socket)

        set_tcp_authopt_key(
            listen_socket,
            tcp_authopt_key(alg=self.get_alg_id(), key=self.master_key),
        )
        set_tcp_authopt_key(
            client_socket,
            tcp_authopt_key(alg=self.get_alg_id(), key=self.master_key),
        )

        # even if one signature is incorrect keep processing the capture
        old_nstat = nstat_json()
        valkey = TcpAuthValidatorKey(key=self.master_key, alg_name=self.alg_name)
        validator = TcpAuthValidator(keys=[valkey])

        try:
            client_socket.settimeout(1.0)
            client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
            for _ in range(5):
                check_socket_echo(client_socket)
        except socket.timeout:
            logger.warning("socket timeout", exc_info=True)
            pass
        client_socket.close()
        session.wait_close()
        sniffer.stop()

        logger.info("capture: %r", sniffer.results)
        for p in sniffer.results:
            validator.handle_packet(p)

        assert not validator.any_fail
        assert not validator.any_unsigned
        # Fails because of duplicate packets:
        # assert not validator.any_incomplete
        new_nstat = nstat_json()
        assert (
            0
            == new_nstat["kernel"]["TcpExtTCPAuthOptFailure"]
            - old_nstat["kernel"]["TcpExtTCPAuthOptFailure"]
        )


def test_has_tcp_authopt():
    from .linux_tcp_authopt import has_tcp_authopt

    assert has_tcp_authopt()


class TestMainV4(MainTestBase):
    address_family = socket.AF_INET


class TestMainV4AES(MainTestBase):
    address_family = socket.AF_INET
    alg_name = "AES-128-CMAC-96"


class TestMainV6(MainTestBase):
    address_family = socket.AF_INET6


def create_capture_socket(ns: str = "", **kw):
    from scapy.config import conf
    from scapy.data import ETH_P_ALL

    with netns_context(ns):
        capture_socket = conf.L2listen(type=ETH_P_ALL, **kw)
    return capture_socket


def test_namespace_fixture(exit_stack: ExitStack):
    nsfixture = exit_stack.enter_context(NamespaceFixture())

    # create sniffer socket
    capture_socket = exit_stack.enter_context(
        create_capture_socket(ns=nsfixture.ns1_name, iface="veth0")
    )

    # create sniffer thread
    session = CompleteTCPCaptureSniffSession(server_port=DEFAULT_TCP_SERVER_PORT)
    sniffer = exit_stack.enter_context(
        AsyncSnifferContext(opened_socket=capture_socket, session=session)
    )

    # create listen socket:
    listen_socket = exit_stack.enter_context(
        create_listen_socket(ns=nsfixture.ns1_name)
    )

    # create client socket:
    with Namespace("/var/run/netns/" + nsfixture.ns2_name, "net"):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)

    # create server thread:
    server_thread = SimpleServerThread(listen_socket, mode="echo")
    exit_stack.enter_context(server_thread)

    # set keys:
    server_key = tcp_authopt_key(
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key="hello",
        send_id=5,
        recv_id=5,
    )
    client_key = tcp_authopt_key(
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key="hello",
        send_id=5,
        recv_id=5,
    )
    set_tcp_authopt_key(listen_socket, server_key)
    set_tcp_authopt_key(client_socket, client_key)

    # Run test test
    client_socket.settimeout(1.0)
    client_socket.connect(("10.10.1.1", DEFAULT_TCP_SERVER_PORT))
    for _ in range(3):
        check_socket_echo(client_socket)
    client_socket.close()

    session.wait_close()
    scapy_sniffer_stop(sniffer)
    plist = sniffer.results
    logger.info("plist: %r", plist)
    assert any((TCP in p and p[TCP].dport == DEFAULT_TCP_SERVER_PORT) for p in plist)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_addr_server_bind(exit_stack: ExitStack, address_family):
    """ "Server only accept client2, check client1 fails"""
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = str(nsfixture.get_addr(address_family, 1, 1))
    client_addr = str(nsfixture.get_addr(address_family, 2, 1))
    client_addr2 = str(nsfixture.get_addr(address_family, 2, 2))

    # create server:
    listen_socket = exit_stack.push(
        create_listen_socket(family=address_family, ns=nsfixture.ns1_name)
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    # set keys:
    server_key = tcp_authopt_key(
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key="hello",
        flags=linux_tcp_authopt.TCP_AUTHOPT_KEY_BIND_ADDR,
        addr=client_addr2,
    )
    set_tcp_authopt(
        listen_socket,
        tcp_authopt(flags=linux_tcp_authopt.TCP_AUTHOPT_FLAG_REJECT_UNEXPECTED),
    )
    set_tcp_authopt_key(listen_socket, server_key)

    # create client socket:
    def create_client_socket():
        with Namespace("/var/run/netns/" + nsfixture.ns2_name, "net"):
            client_socket = socket.socket(address_family, socket.SOCK_STREAM)
        client_key = tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
            key="hello",
        )
        set_tcp_authopt_key(client_socket, client_key)
        return client_socket

    # addr match:
    # with create_client_socket() as client_socket2:
    #    client_socket2.bind((client_addr2, 0))
    #    client_socket2.settimeout(1.0)
    #    client_socket2.connect((server_addr, TCP_SERVER_PORT))

    # addr mismatch:
    with create_client_socket() as client_socket1:
        client_socket1.bind((client_addr, 0))
        with pytest.raises(socket.timeout):
            client_socket1.settimeout(1.0)
            client_socket1.connect((server_addr, DEFAULT_TCP_SERVER_PORT))


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_addr_client_bind(exit_stack: ExitStack, address_family):
    """ "Client configures different keys with same id but different addresses"""
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr1 = str(nsfixture.get_addr(address_family, 1, 1))
    server_addr2 = str(nsfixture.get_addr(address_family, 1, 2))
    client_addr = str(nsfixture.get_addr(address_family, 2, 1))

    # create servers:
    listen_socket1 = exit_stack.enter_context(
        create_listen_socket(
            family=address_family, ns=nsfixture.ns1_name, bind_addr=server_addr1
        )
    )
    listen_socket2 = exit_stack.enter_context(
        create_listen_socket(
            family=address_family, ns=nsfixture.ns1_name, bind_addr=server_addr2
        )
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket1, mode="echo"))
    exit_stack.enter_context(SimpleServerThread(listen_socket2, mode="echo"))

    # set keys:
    set_tcp_authopt_key(
        listen_socket1,
        tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
            key="11111",
        ),
    )
    set_tcp_authopt_key(
        listen_socket2,
        tcp_authopt_key(
            alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
            key="22222",
        ),
    )

    # create client socket:
    def create_client_socket():
        with netns_context(nsfixture.ns2_name):
            client_socket = socket.socket(address_family, socket.SOCK_STREAM)
        set_tcp_authopt_key(
            client_socket,
            tcp_authopt_key(
                alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
                key="11111",
                flags=linux_tcp_authopt.TCP_AUTHOPT_KEY_BIND_ADDR,
                addr=server_addr1,
            ),
        )
        set_tcp_authopt_key(
            client_socket,
            tcp_authopt_key(
                alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
                key="22222",
                flags=linux_tcp_authopt.TCP_AUTHOPT_KEY_BIND_ADDR,
                addr=server_addr2,
            ),
        )
        client_socket.settimeout(1.0)
        client_socket.bind((client_addr, 0))
        return client_socket

    with create_client_socket() as client_socket1:
        client_socket1.connect((server_addr1, DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket1)
    with create_client_socket() as client_socket2:
        client_socket2.connect((server_addr2, DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket2)
