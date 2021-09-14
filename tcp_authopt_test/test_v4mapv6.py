# SPDX-License-Identifier: GPL-2.0
"""By default any IPv6 server will also receive packets from IPv4 clients

This is not currently supported by TCP_AUTHOPT but it should fail in an orderly
manner rather than crash ebcause of incorrect casts.
"""

from contextlib import nullcontext
import logging
import socket
import pytest

from . import linux_tcp_authopt
from .server import SimpleServerThread
from .netns_fixture import NamespaceFixture
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_listen_socket,
    create_client_socket,
)

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("use_tcp_authopt", [True, False])
def test_v4mapv6(exit_stack, use_tcp_authopt: bool):
    """Test ipv4 client and ipv6 server with and without TCP-AO"""
    nsfixture = NamespaceFixture()
    exit_stack.enter_context(nsfixture)
    server_ipv4_addr = nsfixture.get_addr(socket.AF_INET, 1)

    listen_socket = create_listen_socket(ns=nsfixture.ns1_name, family=socket.AF_INET6)
    listen_socket = exit_stack.enter_context(listen_socket)

    server_thread = SimpleServerThread(listen_socket, mode="echo")
    exit_stack.enter_context(server_thread)

    client_socket = create_client_socket(
        ns=nsfixture.ns2_name,
        family=socket.AF_INET,
    )
    client_socket = exit_stack.push(client_socket)

    if use_tcp_authopt:
        alg = linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96
        key = linux_tcp_authopt.tcp_authopt_key(alg=alg, key="hello")
        linux_tcp_authopt.set_tcp_authopt_key(listen_socket, key)
        linux_tcp_authopt.set_tcp_authopt_key(client_socket, key)

    with pytest.raises(socket.timeout) if use_tcp_authopt else nullcontext():
        client_socket.connect((str(server_ipv4_addr), DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket)
    client_socket.close()
