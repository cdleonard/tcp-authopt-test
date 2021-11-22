# SPDX-License-Identifier: GPL-2.0
"""Test TCP-AO keys can be bound to specific remote addresses"""
import socket
from contextlib import ExitStack

import pytest

from .conftest import raises_optional_exception, skipif_missing_tcp_authopt
from .linux_tcp_authopt import (
    TCP_AUTHOPT_ALG,
    TCP_AUTHOPT_FLAG,
    set_tcp_authopt,
    set_tcp_authopt_key_kwargs,
    tcp_authopt,
)
from .netns_fixture import NamespaceFixture
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_client_socket,
    create_listen_socket,
)

pytestmark = skipif_missing_tcp_authopt


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_addr_server_bind(exit_stack: ExitStack, address_family):
    """Server has key bound to client_addr2 so client1 fails and client2 works"""
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = str(nsfixture.get_addr(address_family, 1, 1))
    client_addr1 = str(nsfixture.get_addr(address_family, 2, 1))
    client_addr2 = str(nsfixture.get_addr(address_family, 2, 2))

    # create server:
    listen_socket = exit_stack.push(
        create_listen_socket(family=address_family, ns=nsfixture.server_netns_name)
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    # set keys:
    set_tcp_authopt_key_kwargs(
        listen_socket,
        key="hello",
        addr=client_addr2,
    )
    set_tcp_authopt(
        listen_socket,
        tcp_authopt(flags=TCP_AUTHOPT_FLAG.REJECT_UNEXPECTED),
    )

    # create client socket:
    def _create_client_socket(bind_addr):
        client_socket = create_client_socket(
            ns=nsfixture.client_netns_name,
            family=address_family,
            bind_addr=bind_addr,
        )
        set_tcp_authopt_key_kwargs(
            client_socket,
            alg=TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
            key="hello",
        )
        return client_socket

    # addr match:
    with _create_client_socket(client_addr2) as client_socket2:
        client_socket2.connect((server_addr, DEFAULT_TCP_SERVER_PORT))

    # addr mismatch:
    with _create_client_socket(client_addr1) as client_socket1:
        with pytest.raises(socket.timeout):
            client_socket1.connect((server_addr, DEFAULT_TCP_SERVER_PORT))


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_addr_client_bind(exit_stack: ExitStack, address_family):
    """Client configures different keys with same id but different addresses"""
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr1 = str(nsfixture.get_addr(address_family, 1, 1))
    server_addr2 = str(nsfixture.get_addr(address_family, 1, 2))
    client_addr = str(nsfixture.get_addr(address_family, 2, 1))

    # create servers:
    listen_socket1 = exit_stack.enter_context(
        create_listen_socket(
            family=address_family,
            ns=nsfixture.server_netns_name,
            bind_addr=server_addr1,
        )
    )
    listen_socket2 = exit_stack.enter_context(
        create_listen_socket(
            family=address_family,
            ns=nsfixture.server_netns_name,
            bind_addr=server_addr2,
        )
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket1, mode="echo"))
    exit_stack.enter_context(SimpleServerThread(listen_socket2, mode="echo"))

    # set keys:
    set_tcp_authopt_key_kwargs(listen_socket1, key="11111")
    set_tcp_authopt_key_kwargs(listen_socket2, key="22222")

    # create client socket:
    def _create_client_socket():
        client_socket = create_client_socket(
            ns=nsfixture.client_netns_name,
            family=address_family,
            bind_addr=client_addr,
        )
        set_tcp_authopt_key_kwargs(
            client_socket,
            key="11111",
            addr=server_addr1,
        )
        set_tcp_authopt_key_kwargs(
            client_socket,
            key="22222",
            addr=server_addr2,
        )
        return client_socket

    with _create_client_socket() as client_socket1:
        client_socket1.connect((server_addr1, DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket1)
    with _create_client_socket() as client_socket2:
        client_socket2.connect((server_addr2, DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket2)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_server_prefixlen(exit_stack: ExitStack, address_family):
    """Server key prefixlen is *.2/31, client can connect from .3 but not from .1"""
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = str(nsfixture.get_server_addr(address_family))
    client_addr1 = str(nsfixture.get_client_addr(address_family, 1))
    client_addr3 = str(nsfixture.get_client_addr(address_family, 3))

    listen_socket = create_listen_socket(
        family=address_family,
        ns=nsfixture.server_netns_name,
        bind_addr=server_addr,
    )
    listen_socket = exit_stack.enter_context(listen_socket)
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    # server key:
    prefixlen = 31 if address_family == socket.AF_INET else 127
    server_key_bind_addr = nsfixture.get_client_addr(address_family, 2)
    set_tcp_authopt_key_kwargs(
        listen_socket,
        key="11111",
        prefixlen=prefixlen,
        addr=server_key_bind_addr,
    )
    server_addr_port = (server_addr, DEFAULT_TCP_SERVER_PORT)

    # create client socket:
    def _create_client_socket(**kw):
        client_socket = create_client_socket(
            ns=nsfixture.client_netns_name,
            family=address_family,
            **kw,
        )
        set_tcp_authopt_key_kwargs(client_socket, key="11111")
        return client_socket

    with _create_client_socket(bind_addr=client_addr3) as client_socket:
        client_socket.connect(server_addr_port)
        check_socket_echo(client_socket)
    with _create_client_socket(bind_addr=client_addr1) as client_socket:
        with pytest.raises(socket.timeout):
            client_socket.connect(server_addr_port)


@pytest.mark.parametrize("samekeyid", [True, False])
def test_sign_bad_keyid(exit_stack: ExitStack, samekeyid: bool):
    """Client and server have different keyid, should fail"""
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = str(nsfixture.get_addr(socket.AF_INET, 1, 1))

    # create server:
    listen_socket = create_listen_socket(ns=nsfixture.server_netns_name)
    listen_socket = exit_stack.enter_context(listen_socket)
    set_tcp_authopt_key_kwargs(listen_socket, key="11111", send_id=1, recv_id=1)
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    # create client socket:
    client_socket = create_client_socket(ns=nsfixture.client_netns_name)
    client_socket = exit_stack.enter_context(client_socket)
    client_keyid = 1 if samekeyid else 2
    set_tcp_authopt_key_kwargs(
        client_socket, key="11111", send_id=client_keyid, recv_id=client_keyid
    )

    with raises_optional_exception(None if samekeyid else socket.error):
        client_socket.connect((server_addr, DEFAULT_TCP_SERVER_PORT))
