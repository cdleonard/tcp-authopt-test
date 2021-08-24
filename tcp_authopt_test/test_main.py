import logging
import os
import socket
import typing
from contextlib import ExitStack, contextmanager
from ipaddress import IPv4Address, IPv6Address
from nsenter import Namespace

import pytest
from scapy.layers.inet import TCP

from . import linux_tcp_authopt
from .linux_tcp_authopt import (
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .full_tcp_sniff_session import FullTCPSniffSession
from .netns_fixture import NamespaceFixture
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    AsyncSnifferContext,
    check_socket_echo,
    create_listen_socket,
    netns_context,
    scapy_sniffer_stop,
)

logger = logging.getLogger(__name__)


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


def test_has_tcp_authopt():
    from .linux_tcp_authopt import has_tcp_authopt

    assert has_tcp_authopt()


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
    session = FullTCPSniffSession(server_port=DEFAULT_TCP_SERVER_PORT)
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
