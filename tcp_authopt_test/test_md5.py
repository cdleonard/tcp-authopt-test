# SPDX-License-Identifier: GPL-2.0
import socket
import pytest
from ipaddress import IPv4Address
from .sockaddr import sockaddr_in
from .server import SimpleServerThread
from .utils import create_listen_socket, check_socket_echo, DEFAULT_TCP_SERVER_PORT
from .linux_tcp_md5sig import setsockopt_md5sig, tcp_md5sig


def test_md5sig_packunpack():
    s1 = tcp_md5sig(flags=0, prefixlen=0, ifindex=0, keylen=0, key=b"a\x00b")
    s2 = tcp_md5sig.unpack(s1.pack())
    assert s1.key[0:2] == s2.key[0:2]
    assert len(s2.key) == 80


def test_md5_basic(exit_stack):
    tcp_md5_key = b"12345"

    listen_socket = exit_stack.enter_context(create_listen_socket())
    setsockopt_md5sig(
        listen_socket,
        key=tcp_md5_key,
        addr=sockaddr_in(addr=IPv4Address("127.0.0.1")),
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    setsockopt_md5sig(
        client_socket,
        key=tcp_md5_key,
        addr=sockaddr_in(addr=IPv4Address("127.0.0.1")),
    )

    client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
    check_socket_echo(client_socket)
