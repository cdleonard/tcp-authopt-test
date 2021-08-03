import logging
import os
import socket
import threading
import time
import errno
import subprocess
import typing
from contextlib import ExitStack
from ipaddress import IPv4Address
from nsenter import Namespace

import pytest
from scapy.layers.inet import TCP
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer
import scapy.sessions

from . import tcp_authopt_alg
from . import linux_tcp_authopt
from .linux_tcp_authopt import (
    del_tcp_authopt_key_by_id,
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .validator import TcpAuthValidator, TcpAuthValidatorKey
from .linux_tcp_md5sig import setsockopt_md5sig, tcp_md5sig
from .server import SimpleServerThread
from .sockaddr import sockaddr_in
from .utils import randbytes
from .utils import recvall
from .utils import nstat_json

logger = logging.getLogger(__name__)


def can_capture():
    # This is too restrictive:
    return os.geteuid() == 0


skipif_cant_capture = pytest.mark.skipif(
    not can_capture(), reason="run as root to capture packets"
)

TCP_SERVER_PORT = 17971


@pytest.fixture
def exit_stack():
    with ExitStack() as exit_stack:
        yield exit_stack


class NamespaceFixture:
    """Create a pair of namespace connect by one veth pair"""

    ns1_name = "tcp_authopt_test_1"
    ns2_name = "tcp_authopt_test_2"
    ns1_addr_list = ["10.0.0.1/16"]
    ns2_addr_list = ["10.0.1.1/16"]

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def __enter__(self):
        script = f"""
set -e -x
ip netns del {self.ns1_name} || true
ip netns del {self.ns2_name} || true
ip netns add {self.ns1_name}
ip netns add {self.ns2_name}
ip link add veth0 netns {self.ns1_name} type veth peer name veth0 netns {self.ns2_name}
ip netns exec {self.ns1_name} ip link set veth0 up
ip netns exec {self.ns2_name} ip link set veth0 up
"""
        for item in self.ns1_addr_list:
            script += f"ip netns exec {self.ns1_name} ip addr add {item} dev veth0\n"
        for item in self.ns2_addr_list:
            script += f"ip netns exec {self.ns2_name} ip addr add {item} dev veth0\n"
        subprocess.run(script, shell=True, check=True)
        return self

    def __exit__(self, *a):
        script = f"""
set -e -x
ip netns del {self.ns1_name} || true
ip netns del {self.ns2_name} || true
"""
        subprocess.run(script, shell=True, check=True)


def check_socket_echo(sock, size=1024):
    """Send random bytes and check they are received"""
    send_buf = randbytes(size)
    sock.sendall(send_buf)
    recv_buf = recvall(sock, size)
    assert send_buf == recv_buf


def test_nonauth_connect(exit_stack):
    tcp_server_host = ""

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket = exit_stack.push(listen_socket)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((tcp_server_host, TCP_SERVER_PORT))
    listen_socket.listen(1)
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    client_socket.connect(("localhost", TCP_SERVER_PORT))
    check_socket_echo(client_socket)


def test_multi_nonauth_connect():
    """Test that the client/server infrastructure does not leak or hang"""
    for i in range(10):
        with ExitStack() as exit_stack:
            logger.info("ITER %d", i)
            test_nonauth_connect(exit_stack)


def test_md5sig_packunpack():
    s1 = tcp_md5sig(flags=0, prefixlen=0, ifindex=0, keylen=0, key=b"a\x00b")
    s2 = tcp_md5sig.unpack(s1.pack())
    assert s1.key[0:2] == s2.key[0:2]
    assert len(s2.key) == 80


def test_md5_basic(exit_stack):
    tcp_server_host = ""
    tcp_md5_key = b"12345"

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket = exit_stack.push(listen_socket)
    setsockopt_md5sig(
        listen_socket,
        key=tcp_md5_key,
        addr=sockaddr_in(addr=IPv4Address("127.0.0.1")),
    )
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((tcp_server_host, TCP_SERVER_PORT))
    listen_socket.listen(1)
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    setsockopt_md5sig(
        client_socket,
        key=tcp_md5_key,
        addr=sockaddr_in(addr=IPv4Address("127.0.0.1")),
    )

    client_socket.connect(("localhost", TCP_SERVER_PORT))
    check_socket_echo(client_socket)


class SimpleWaitEvent(threading.Event):
    @property
    def value(self) -> bool:
        return self.is_set()

    @value.setter
    def value(self, value: bool):
        if value:
            self.set()
        else:
            self.clear()

    def wait(self, timeout=None):
        """Like Event.wait except raise on timeout"""
        super().wait(timeout)
        if not self.is_set():
            raise TimeoutError(f"Timed out timeout={timeout!r}")


def scapy_sniffer_start_block(sniffer: AsyncSniffer, timeout=1):
    """Like AsyncSniffer.start except block until sniffing starts

    This ensures no lost packets and no delays
    """
    if sniffer.kwargs.get("started_callback"):
        raise ValueError("sniffer must not already have a started_callback")

    e = SimpleWaitEvent()
    sniffer.kwargs["started_callback"] = e.set
    sniffer.start()
    e.wait(timeout=timeout)


def scapy_sniffer_stop(sniffer: AsyncSniffer):
    """Like AsyncSniffer.stop except no error is raising if not running"""
    if sniffer is not None and sniffer.running:
        sniffer.stop()


class Context:
    sniffer: AsyncSniffer

    def __init__(
        self,
        should_sniff: bool = True,
        address_family=socket.AF_INET,
        sniffer_kwargs=None,
    ):
        self.should_sniff = should_sniff
        self.address_family = address_family
        self.sniffer_kwargs = sniffer_kwargs

    def stop_sniffer(self):
        scapy_sniffer_stop(self.sniffer)

    def start(self):
        self.exit_stack = ExitStack()
        if self.should_sniff:
            self.sniffer = AsyncSniffer(
                filter=f"tcp port {TCP_SERVER_PORT}",
                iface="lo",
                **(self.sniffer_kwargs or {}),
            )
            scapy_sniffer_start_block(self.sniffer)
            self.exit_stack.callback(self.stop_sniffer)

        self.listen_socket = socket.socket(self.address_family, socket.SOCK_STREAM)
        self.listen_socket = self.exit_stack.push(self.listen_socket)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind(("", TCP_SERVER_PORT))
        self.listen_socket.listen(1)

        self.client_socket = socket.socket(self.address_family, socket.SOCK_STREAM)
        self.client_socket = self.exit_stack.push(self.client_socket)

        self.server_thread = SimpleServerThread(self.listen_socket, mode="echo")
        self.exit_stack.enter_context(self.server_thread)

    def stop(self):
        self.exit_stack.close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def test_connect_nosniff():
    with Context(should_sniff=False) as context:
        context.client_socket.connect(("localhost", TCP_SERVER_PORT))


@skipif_cant_capture
def test_sniff_nothing():
    """Test the scapy sniffer can start and stop."""
    sniffer = AsyncSniffer(filter=f"tcp port {TCP_SERVER_PORT}", iface="lo")
    scapy_sniffer_start_block(sniffer)
    sniffer.stop()


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
    session = CompleteTCPCaptureSniffSession(server_port=TCP_SERVER_PORT)
    context = exit_stack.enter_context(Context(sniffer_kwargs=dict(session=session)))
    context.client_socket.connect(("localhost", TCP_SERVER_PORT))
    check_socket_echo(context.client_socket)
    context.client_socket.close()
    session.wait_close()
    context.sniffer.stop()

    found_syn = False
    found_synack = False
    found_client_fin = False
    found_server_fin = False
    for p in context.sniffer.results:
        th = p[TCP]
        logger.info("sport=%d dport=%d flags=%s", th.sport, th.dport, th.flags)
        if p[TCP].flags.S and not p[TCP].flags.A:
            assert p[TCP].dport == TCP_SERVER_PORT
            found_syn = True
        if p[TCP].flags.S and p[TCP].flags.A:
            assert p[TCP].sport == TCP_SERVER_PORT
            found_synack = True
        if p[TCP].flags.F:
            if p[TCP].dport == TCP_SERVER_PORT:
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
        context = exit_stack.enter_context(Context(address_family=self.address_family))

        set_tcp_authopt(context.listen_socket, tcp_authopt(send_local_id=1))
        server_key = tcp_authopt_key(
            local_id=1, alg=self.get_alg_id(), key=self.master_key
        )
        set_tcp_authopt_key(context.listen_socket, server_key)
        set_tcp_authopt(context.client_socket, tcp_authopt(send_local_id=1))
        client_key = tcp_authopt_key(
            local_id=1, alg=self.get_alg_id(), key=self.master_key
        )
        set_tcp_authopt_key(context.client_socket, client_key)

        # even if one signature is incorrect keep processing the capture
        old_nstat = nstat_json()
        valkey = TcpAuthValidatorKey(key=self.master_key, alg_name=self.alg_name)
        validator = TcpAuthValidator(keys=[valkey])

        try:
            context.client_socket.settimeout(1.0)
            context.client_socket.connect(("localhost", TCP_SERVER_PORT))
            for _ in range(5):
                check_socket_echo(context.client_socket)
        except socket.timeout:
            logger.warning("socket timeout", exc_info=True)
            pass
        context.client_socket.close()
        time.sleep(1)
        context.sniffer.stop()

        logger.info("capture: %r", context.sniffer.results)
        for p in context.sniffer.results:
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


def test_tcp_authopt_key_del_without_active(exit_stack):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exit_stack.push(sock)

    # nothing happens:
    with pytest.raises(OSError) as e:
        del_tcp_authopt_key_by_id(sock, 1)
    assert e.value.errno == errno.EINVAL


def test_tcp_authopt_key_setdel(exit_stack):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exit_stack.push(sock)
    set_tcp_authopt(sock, tcp_authopt(send_local_id=0))

    # delete returns ENOENT
    with pytest.raises(OSError) as e:
        del_tcp_authopt_key_by_id(sock, 1)
    assert e.value.errno == errno.ENOENT
    key = tcp_authopt_key(local_id=1, key=b"123")

    # add and del
    set_tcp_authopt_key(sock, key)
    del_tcp_authopt_key_by_id(sock, key.local_id)

    # duplicate delete returns ENOENT
    with pytest.raises(OSError) as e:
        del_tcp_authopt_key_by_id(sock, 1)
    assert e.value.errno == errno.ENOENT


class TestMainV4(MainTestBase):
    address_family = socket.AF_INET


class TestMainV4AES(MainTestBase):
    address_family = socket.AF_INET
    alg_name = "AES-128-CMAC-96"


class TestMainV6(MainTestBase):
    address_family = socket.AF_INET6


def test_namespace_fixture(exit_stack: ExitStack):
    nsfixture = exit_stack.enter_context(NamespaceFixture())

    # create sniffer socket
    with Namespace("/var/run/netns/" + nsfixture.ns1_name, "net"):
        from scapy.config import conf
        from scapy.data import ETH_P_ALL
        capture_socket = conf.L2listen(type=ETH_P_ALL, iface="veth0", filter=f"tcp port {TCP_SERVER_PORT}")
    capture_socket = exit_stack.push(capture_socket)

    # create sniffer thread
    session = CompleteTCPCaptureSniffSession(server_port=TCP_SERVER_PORT)
    sniffer = AsyncSniffer(opened_socket=capture_socket, session=session)
    scapy_sniffer_start_block(sniffer)
    exit_stack.callback(lambda: scapy_sniffer_stop(sniffer))

    # create listen socket:
    with Namespace("/var/run/netns/" + nsfixture.ns1_name, "net"):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket = exit_stack.push(listen_socket)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind(("10.0.0.1", TCP_SERVER_PORT))
    listen_socket.listen(1)

    # create client socket:
    with Namespace("/var/run/netns/" + nsfixture.ns2_name, "net"):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)

    # create server thread:
    server_thread = SimpleServerThread(listen_socket, mode="echo")
    exit_stack.enter_context(server_thread)

    # set keys:
    server_key = tcp_authopt_key(
        local_id=1,
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key="hello",
        send_id=5,
        recv_id=5,
    )
    client_key = tcp_authopt_key(
        local_id=1,
        alg=linux_tcp_authopt.TCP_AUTHOPT_ALG_HMAC_SHA_1_96,
        key="hello",
        send_id=5,
        recv_id=5,
    )
    set_tcp_authopt(listen_socket, tcp_authopt(send_local_id=1))
    set_tcp_authopt_key(listen_socket, server_key)
    set_tcp_authopt(client_socket, tcp_authopt(send_local_id=1))
    set_tcp_authopt_key(client_socket, client_key)

    # Run test test
    client_socket.settimeout(1.0)
    client_socket.connect(("10.0.0.1", TCP_SERVER_PORT))
    for _ in range(3):
        check_socket_echo(client_socket)
    client_socket.close()

    session.wait_close()
    scapy_sniffer_stop(sniffer)
    plist = sniffer.results
    logger.info("plist: %r", plist)
    assert any((TCP in p and p[TCP].dport == TCP_SERVER_PORT) for p in plist)
