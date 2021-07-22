import logging
import os
import socket
import time
import errno
import typing
from contextlib import ExitStack
from ipaddress import IPv4Address

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

from . import tcp_authopt_alg
from . import linux_tcp_authopt
from .linux_tcp_authopt import (
    del_tcp_authopt_key_by_id,
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .linux_tcp_md5sig import setsockopt_md5sig, tcp_md5sig
from .server import SimpleServerThread
from .sockaddr import sockaddr_in
from .utils import randbytes
from .utils import recvall
from .utils import nstat_json
from .utils import scapy_tcp_get_authopt_val

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
        addr=sockaddr_in(port=0, addr=IPv4Address("127.0.0.1")),
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
        addr=sockaddr_in(port=TCP_SERVER_PORT, addr=IPv4Address("127.0.0.1")),
    )

    client_socket.connect(("localhost", TCP_SERVER_PORT))
    check_socket_echo(client_socket)


def scapy_sniffer_start_spin(sniffer: AsyncSniffer):
    sniffer.start()
    for i in range(500):
        if getattr(sniffer, "stop_cb", None) is not None:
            return True
        time.sleep(0.01)
    return False


class Context:
    sniffer: AsyncSniffer

    def __init__(self, should_sniff: bool = True, address_family=socket.AF_INET):
        self.should_sniff = should_sniff
        self.address_family = address_family

    def stop_sniffer(self):
        if self.sniffer and self.sniffer.running:
            self.sniffer.stop()

    def start(self):
        self.exit_stack = ExitStack()
        if self.should_sniff:
            self.sniffer = AsyncSniffer(
                filter=f"tcp port {TCP_SERVER_PORT}", iface="lo"
            )
            scapy_sniffer_start_spin(self.sniffer)
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
    scapy_sniffer_start_spin(sniffer)
    sniffer.stop()


@skipif_cant_capture
def test_complete_sniff(exit_stack: ExitStack):
    """Test that the whole TCP conversation is sniffed by scapy"""
    context = exit_stack.enter_context(Context())
    context.client_socket.connect(("localhost", TCP_SERVER_PORT))
    check_socket_echo(context.client_socket)
    context.client_socket.close()
    time.sleep(1)
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

    def kdf(self, context: bytes) -> bytes:
        return self.get_alg().kdf(self.master_key, context)

    def mac(self, traffic_key: bytes, message_bytes: bytes) -> bytes:
        return self.get_alg().mac(traffic_key, message_bytes)

    def mac_from_scapy_packet(
        self, traffic_key: bytes, packet: Packet, include_options=True
    ) -> bytes:
        message_bytes = tcp_authopt_alg.build_message_from_scapy(
            packet, include_options=include_options
        )
        return self.mac(traffic_key, message_bytes)

    @skipif_cant_capture
    def test_authopt_connect_sniff(self, exit_stack: ExitStack):
        context = exit_stack.enter_context(Context(address_family=self.address_family))

        set_tcp_authopt(context.listen_socket, tcp_authopt(send_local_id=1))
        server_key = tcp_authopt_key(local_id=1, alg=self.get_alg_id(), key=self.master_key)
        set_tcp_authopt_key(context.listen_socket, server_key)
        set_tcp_authopt(context.client_socket, tcp_authopt(send_local_id=1))
        client_key = tcp_authopt_key(local_id=1, alg=self.get_alg_id(), key=self.master_key)
        set_tcp_authopt_key(context.client_socket, client_key)

        # even if one signature is incorrect keep processing the capture
        fail = False
        found_syn = False
        found_synack = False
        old_nstat = nstat_json()

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

        auth_context = tcp_authopt_alg.TCPAuthContext()

        logger.info("capture: %r", context.sniffer.results)
        for p in context.sniffer.results:
            # check packet matches address family
            if self.address_family == socket.AF_INET:
                assert IP in p
            elif self.address_family == socket.AF_INET6:
                assert IPv6 in p
            # check packets is only for our packet
            assert p[TCP].sport == TCP_SERVER_PORT or p[TCP].dport == TCP_SERVER_PORT

            opt = scapy_tcp_get_authopt_val(p[TCP])
            if opt is None:
                logger.error("missing tcp-ao on packet %r", p)
                fail = True
                continue
            assert opt is not None
            assert opt.keyid == 0
            # logger.info("opt: %r", opt)
            # logger.info("flags: %r", p[TCP].flags)
            # logger.info("p[TCP]: %r", p[TCP])
            # logger.info("p[IP]: %r", p[IP])

            if p[TCP].flags.S and not p[TCP].flags.A:
                assert p[TCP].dport == TCP_SERVER_PORT
                context_bytes = tcp_authopt_alg.build_context_from_scapy(
                    p, p[TCP].seq, 0
                )
                auth_context.init_from_syn_packet(p)
                assert auth_context.pack(syn=True) == context_bytes
                found_syn = True
            elif p[TCP].flags.S and p[TCP].flags.A:
                assert p[TCP].sport == TCP_SERVER_PORT
                assert found_syn
                context_bytes = tcp_authopt_alg.build_context_from_scapy(
                    p, p[TCP].seq, p[TCP].ack - 1
                )
                auth_context.update_from_synack_packet(p)
                assert auth_context.pack(rev=True).hex() == context_bytes.hex()
                found_synack = True
            else:
                assert found_synack
                context_bytes = auth_context.pack(rev=(p[TCP].sport == TCP_SERVER_PORT))

            # logger.info("context=%s packet=%r", context_bytes.hex(" "), p);
            traffic_key = self.kdf(context_bytes)
            computed_mac = self.mac_from_scapy_packet(traffic_key, p)
            captured_mac = opt.mac
            if computed_mac != captured_mac:
                fail = True
                logger.error(
                    "fail computed_mac=%s != captured_mac=%s traffic_key=%s context=%s packet=%r",
                    computed_mac.hex(" "),
                    opt.mac.hex(" "),
                    traffic_key.hex(" "),
                    context_bytes.hex(" "),
                    p,
                )
            else:
                logger.info("correct mac=%s packet=%r", computed_mac.hex(" "), p)
            # assert computed_mac == opt.mac

        new_nstat = nstat_json()
        assert (
            0
            == new_nstat["kernel"]["TcpExtTCPAuthOptFailure"]
            - old_nstat["kernel"]["TcpExtTCPAuthOptFailure"]
        )
        assert found_syn
        assert found_synack
        assert not fail


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
