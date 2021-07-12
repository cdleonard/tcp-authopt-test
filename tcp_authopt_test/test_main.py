import logging
import os
import socket
import random
import time
import typing
from contextlib import ExitStack
from dataclasses import dataclass
from ipaddress import IPv4Address

import pytest
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

from . import tcp_authopt_alg
from .linux_tcp_authopt import (
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .linux_tcp_md5sig import setsockopt_md5sig, tcp_md5sig
from .server import SimpleServerThread
from .sockaddr import sockaddr_in

logger = logging.getLogger(__name__)


def can_capture():
    # This is too restrictive:
    return os.geteuid() == 0


skipif_cant_capture = pytest.mark.skipif(
    not can_capture(), reason="run as root to capture packets"
)

TCP_SERVER_PORT = 17971


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
    return bytes([random.randint(0, 255) for index in range(count)])


@pytest.fixture
def exit_stack():
    with ExitStack() as exit_stack:
        yield exit_stack


def test_nonauth_connect(exit_stack):
    tcp_server_host = ""

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket = exit_stack.push(listen_socket)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((tcp_server_host, TCP_SERVER_PORT))
    listen_socket.listen(1)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)

    server_thread = SimpleServerThread(listen_socket, mode="echo")
    server_thread.start()
    exit_stack.callback(server_thread.stop)

    client_socket.connect(("localhost", TCP_SERVER_PORT))

    client_socket.sendall(b"0" * 3000)
    buf = recvall(client_socket, 3000)
    assert len(buf) == 3000


def test_multi():
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
        keylen=len(tcp_md5_key),
        key=tcp_md5_key,
        addr=sockaddr_in(port=0, addr=IPv4Address("127.0.0.1")),
    )
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((tcp_server_host, TCP_SERVER_PORT))
    listen_socket.listen(1)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    setsockopt_md5sig(
        client_socket,
        keylen=len(tcp_md5_key),
        key=tcp_md5_key,
        addr=sockaddr_in(port=TCP_SERVER_PORT, addr=IPv4Address("127.0.0.1")),
    )

    server_thread = SimpleServerThread(listen_socket, mode="echo")
    server_thread.start()
    exit_stack.callback(server_thread.stop)

    client_socket.connect(("localhost", TCP_SERVER_PORT))

    client_socket.sendall(b"0" * 3000)
    buf = recvall(client_socket, 3000)
    assert len(buf) == 3000


def scapy_sniffer_start_spin(sniffer: AsyncSniffer):
    sniffer.start()
    for i in range(500):
        if getattr(sniffer, "stop_cb", None) is not None:
            return True
        time.sleep(0.01)
    return False


class Context:
    sniffer: AsyncSniffer

    def __init__(self, should_sniff: bool = True):
        self.should_sniff = should_sniff

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

        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket = self.exit_stack.push(self.listen_socket)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind(("", TCP_SERVER_PORT))
        self.listen_socket.listen(1)

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket = self.exit_stack.push(self.client_socket)

        self.server_thread = SimpleServerThread(self.listen_socket, mode="echo")
        self.server_thread.start()
        self.exit_stack.callback(self.server_thread.stop)

    def stop(self):
        self.exit_stack.close()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


@dataclass
class tcphdr_authopt:
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
        if optnum == 29:
            return tcphdr_authopt.unpack(optval)
    return None


class TestMain:
    """Eventually this should be paratrized based on ipv and alg"""

    master_key = b"testvector"

    def kdf(self, context: bytes) -> bytes:
        return tcp_authopt_alg.kdf_sha1(self.master_key, context)

    def mac(self, traffic_key: bytes, message_bytes: bytes) -> bytes:
        return tcp_authopt_alg.mac_sha1(traffic_key, message_bytes)

    def mac_from_scapy_packet(
        self, traffic_key: bytes, packet: Packet, include_options=True
    ) -> bytes:
        message_bytes = tcp_authopt_alg.build_message_from_scapy(
            packet, include_options=include_options
        )
        return self.mac(traffic_key, message_bytes)

    def test_connect_nosniff(self):
        with Context(should_sniff=False) as context:
            context.client_socket.connect(("localhost", TCP_SERVER_PORT))

    @skipif_cant_capture
    def test_connect_sniff(self):
        with Context() as context:
            context.client_socket.connect(("localhost", TCP_SERVER_PORT))
            time.sleep(1)
            context.sniffer.stop()

            found_syn = False
            found_synack = False
            for p in context.sniffer.results:
                if p[TCP].flags.S and not p[TCP].flags.A:
                    assert p[TCP].dport == TCP_SERVER_PORT
                    found_syn = True
                if p[TCP].flags.S and p[TCP].flags.A:
                    assert p[TCP].sport == TCP_SERVER_PORT
                    found_synack = True
            assert found_syn
            assert found_synack

    @skipif_cant_capture
    def test_sniffer_works(self):
        sniffer = AsyncSniffer(filter=f"tcp port {TCP_SERVER_PORT}", iface="lo")
        scapy_sniffer_start_spin(sniffer)
        sniffer.stop()

    @skipif_cant_capture
    def test_authopt_connect_sniff(self):
        with Context() as context:
            set_tcp_authopt(context.listen_socket, tcp_authopt(send_local_id=1))
            set_tcp_authopt_key(
                context.listen_socket, tcp_authopt_key(local_id=1, key=self.master_key)
            )
            set_tcp_authopt(context.client_socket, tcp_authopt(send_local_id=1))
            set_tcp_authopt_key(
                context.client_socket, tcp_authopt_key(local_id=1, key=self.master_key)
            )
            context.client_socket.settimeout(1.0);
            context.client_socket.connect(("localhost", TCP_SERVER_PORT))

            for index in range(2):
                buf = randbytes(128)
                assert len(buf) == 128
                context.client_socket.sendall(buf)
                recv_buf = recvall(context.client_socket, len(buf))
                assert recv_buf == buf

            context.client_socket.close()
            time.sleep(1)
            context.sniffer.stop()

            fail = False
            found_syn = False
            found_synack = False
            auth_context = tcp_authopt_alg.TCPAuthContext()

            logger.info("capture: %r", context.sniffer.results)
            for p in context.sniffer.results:
                opt = scapy_tcp_get_authopt_val(p[TCP])
                assert p[TCP].sport == TCP_SERVER_PORT or p[TCP].dport == TCP_SERVER_PORT
                if opt is None:
                    # this should be an error
                    logger.error("missing tcp-ao on packet %r", p)
                    fail = True
                    continue
                assert opt is not None
                assert opt.keyid == 0
                #logger.info("opt: %r", opt)
                #logger.info("flags: %r", p[TCP].flags)
                #logger.info("p[TCP]: %r", p[TCP])
                #logger.info("p[IP]: %r", p[IP])

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
                    assert auth_context.pack(rev=True).hex(" ") == context_bytes.hex(" ")
                    found_synack = True
                else:
                    assert found_synack
                    context_bytes = auth_context.pack(rev=(p[TCP].sport == TCP_SERVER_PORT))

                traffic_key = self.kdf(context_bytes)
                computed_mac = self.mac_from_scapy_packet(traffic_key, p)
                captured_mac = opt.mac
                if computed_mac != captured_mac:
                    logger.error("fail computed_mac=%s != captured_mac=%s traffic_key=%s context=%s packet=%r",
                            computed_mac.hex(" "), opt.mac.hex(" "),
                            traffic_key.hex(" "),
                            context_bytes.hex(" "),
                            p)
                    fail = True
                else:
                    logger.info("correct mac=%s packet=%r", computed_mac.hex(" "), p)
                #assert computed_mac == opt.mac

            assert found_syn
            assert found_synack
            assert not fail
