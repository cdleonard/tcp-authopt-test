# SPDX-License-Identifier: GPL-2.0
import logging
import socket
import typing
from contextlib import ExitStack, contextmanager

import pytest

from .conftest import skipif_missing_tcp_authopt
from .linux_tcp_authopt import (
    TCP_AUTHOPT_FLAG,
    get_tcp_authopt,
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .server import SimpleServerThread
from .utils import DEFAULT_TCP_SERVER_PORT, check_socket_echo, create_listen_socket

pytestmark = skipif_missing_tcp_authopt
logger = logging.getLogger(__name__)


@contextmanager
def make_tcp_authopt_socket_pair(
    server_addr="127.0.0.1",
    server_authopt: tcp_authopt = None,
    server_key_list: typing.Iterable[tcp_authopt_key] = [],
    client_authopt: tcp_authopt = None,
    client_key_list: typing.Iterable[tcp_authopt_key] = [],
) -> typing.Iterator[typing.Tuple[socket.socket, socket.socket]]:
    """Make a pair for connected sockets for key switching tests

    Server runs in a background thread implementing echo protocol"""
    with ExitStack() as exit_stack:
        listen_socket = exit_stack.enter_context(
            create_listen_socket(bind_addr=server_addr)
        )
        server_thread = exit_stack.enter_context(
            SimpleServerThread(listen_socket, mode="echo")
        )
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(1.0)

        if server_authopt:
            set_tcp_authopt(listen_socket, server_authopt)
        for k in server_key_list:
            set_tcp_authopt_key(listen_socket, k)
        if client_authopt:
            set_tcp_authopt(client_socket, client_authopt)
        for k in client_key_list:
            set_tcp_authopt_key(client_socket, k)

        client_socket.connect((server_addr, DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket)
        server_socket = server_thread.server_socket[0]

        yield client_socket, server_socket


def test_get_keyids(exit_stack: ExitStack):
    """Check reading key ids"""
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    ck1 = tcp_authopt_key(send_id=12, recv_id=11, key="111")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1],
            client_key_list=[ck1],
        )
    )

    check_socket_echo(client_socket)
    client_tcp_authopt = get_tcp_authopt(client_socket)
    server_tcp_authopt = get_tcp_authopt(server_socket)
    assert server_tcp_authopt.send_keyid == 11
    assert server_tcp_authopt.send_rnextkeyid == 12
    assert server_tcp_authopt.recv_keyid == 12
    assert server_tcp_authopt.recv_rnextkeyid == 11
    assert client_tcp_authopt.send_keyid == 12
    assert client_tcp_authopt.send_rnextkeyid == 11
    assert client_tcp_authopt.recv_keyid == 11
    assert client_tcp_authopt.recv_rnextkeyid == 12


def test_rollover_send_keyid(exit_stack: ExitStack):
    """Check reading key ids"""
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    sk2 = tcp_authopt_key(send_id=21, recv_id=22, key="222")
    ck1 = tcp_authopt_key(send_id=12, recv_id=11, key="111")
    ck2 = tcp_authopt_key(send_id=22, recv_id=21, key="222")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1, sk2],
            client_key_list=[ck1, ck2],
            client_authopt=tcp_authopt(
                send_keyid=12, flags=TCP_AUTHOPT_FLAG.LOCK_KEYID
            ),
        )
    )

    check_socket_echo(client_socket)
    assert get_tcp_authopt(client_socket).recv_keyid == 11
    assert get_tcp_authopt(server_socket).recv_keyid == 12

    # Explicit request for key2
    set_tcp_authopt(
        client_socket, tcp_authopt(send_keyid=22, flags=TCP_AUTHOPT_FLAG.LOCK_KEYID)
    )
    check_socket_echo(client_socket)
    assert get_tcp_authopt(client_socket).recv_keyid == 21
    assert get_tcp_authopt(server_socket).recv_keyid == 22


def test_rollover_rnextkeyid(exit_stack: ExitStack):
    """Check reading key ids"""
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    sk2 = tcp_authopt_key(send_id=21, recv_id=22, key="222")
    ck1 = tcp_authopt_key(send_id=12, recv_id=11, key="111")
    ck2 = tcp_authopt_key(send_id=22, recv_id=21, key="222")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1],
            client_key_list=[ck1, ck2],
            client_authopt=tcp_authopt(
                send_keyid=12, flags=TCP_AUTHOPT_FLAG.LOCK_KEYID
            ),
        )
    )

    check_socket_echo(client_socket)
    assert get_tcp_authopt(server_socket).recv_rnextkeyid == 11

    # request rnextkeyd=22 but server does not have it
    set_tcp_authopt(
        client_socket,
        tcp_authopt(send_rnextkeyid=21, flags=TCP_AUTHOPT_FLAG.LOCK_RNEXTKEYID),
    )
    check_socket_echo(client_socket)
    check_socket_echo(client_socket)
    assert get_tcp_authopt(server_socket).recv_rnextkeyid == 21
    assert get_tcp_authopt(server_socket).send_keyid == 11

    # after adding k2 on server the key is switched
    set_tcp_authopt_key(server_socket, sk2)
    check_socket_echo(client_socket)
    check_socket_echo(client_socket)
    assert get_tcp_authopt(server_socket).send_keyid == 21


def test_rollover_delkey(exit_stack: ExitStack):
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    sk2 = tcp_authopt_key(send_id=21, recv_id=22, key="222")
    ck1 = tcp_authopt_key(send_id=12, recv_id=11, key="111")
    ck2 = tcp_authopt_key(send_id=22, recv_id=21, key="222")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1, sk2],
            client_key_list=[ck1, ck2],
            client_authopt=tcp_authopt(
                send_keyid=12, flags=TCP_AUTHOPT_FLAG.LOCK_KEYID
            ),
        )
    )

    check_socket_echo(client_socket)
    assert get_tcp_authopt(server_socket).recv_keyid == 12

    # invalid send_keyid is just ignored
    set_tcp_authopt(client_socket, tcp_authopt(send_keyid=7))
    check_socket_echo(client_socket)
    assert get_tcp_authopt(client_socket).send_keyid == 12
    assert get_tcp_authopt(server_socket).recv_keyid == 12
    assert get_tcp_authopt(client_socket).recv_keyid == 11

    # If a key is removed it is replaced by anything that matches
    ck1.delete_flag = True
    set_tcp_authopt_key(client_socket, ck1)
    check_socket_echo(client_socket)
    check_socket_echo(client_socket)
    assert get_tcp_authopt(client_socket).send_keyid == 22
    assert get_tcp_authopt(server_socket).send_keyid == 21
    assert get_tcp_authopt(server_socket).recv_keyid == 22
    assert get_tcp_authopt(client_socket).recv_keyid == 21


@pytest.mark.xfail()
def test_synack_with_syn_rnextkeyid(exit_stack: ExitStack):
    """Server has more keys than client but it responds based on rnextkeyid in SYN

    Responding with any other key will cause the client to drop the synack
    """
    sk1 = tcp_authopt_key(send_id=11, recv_id=12, key="111")
    sk2 = tcp_authopt_key(send_id=21, recv_id=32, key="222")
    sk3 = tcp_authopt_key(send_id=31, recv_id=32, key="333")
    ck = tcp_authopt_key(send_id=22, recv_id=21, key="222")
    client_socket, server_socket = exit_stack.enter_context(
        make_tcp_authopt_socket_pair(
            server_key_list=[sk1, sk2, sk3],
            client_key_list=[ck],
        )
    )

    check_socket_echo(client_socket)
    server_tcp_authopt = get_tcp_authopt(server_socket)
    assert server_tcp_authopt.send_keyid == ck.recv_id
    assert server_tcp_authopt.recv_rnextkeyid == ck.send_id


def test_norecv_reject():
    context = make_tcp_authopt_socket_pair(
        server_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111", norecv=True),
            tcp_authopt_key(send_id=2, recv_id=2, key="222"),
        ],
        client_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111"),
            tcp_authopt_key(send_id=2, recv_id=2, key="222"),
        ],
        client_authopt=tcp_authopt(send_keyid=1, flags=TCP_AUTHOPT_FLAG.LOCK_KEYID),
    )
    with pytest.raises(OSError):
        with context:
            logger.info("unexpected success")


def test_nosend_accept_recv():
    """Client sends key 1, server accepts it but because of "nosend" flag it responds with key 2"""
    context = make_tcp_authopt_socket_pair(
        server_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111", nosend=True),
            tcp_authopt_key(send_id=2, recv_id=2, key="222"),
        ],
        client_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111"),
            tcp_authopt_key(send_id=2, recv_id=2, key="222"),
        ],
        client_authopt=tcp_authopt(send_keyid=1, flags=TCP_AUTHOPT_FLAG.LOCK_KEYID),
    )
    with context as (client_socket, server_socket):
        check_socket_echo(client_socket)
        assert get_tcp_authopt(server_socket).send_keyid == 2
        # client still sends key1 because it is locked
        assert get_tcp_authopt(client_socket).recv_rnextkeyid == 2
        assert get_tcp_authopt(client_socket).send_keyid == 1


def test_norecv_accept_send():
    """Server accepts switch to key2 which is marked norecv"""
    context = make_tcp_authopt_socket_pair(
        server_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111"),
            tcp_authopt_key(send_id=2, recv_id=2, key="222", norecv=True),
        ],
        client_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111"),
            tcp_authopt_key(send_id=2, recv_id=2, key="222"),
        ],
        client_authopt=tcp_authopt(
            flags=TCP_AUTHOPT_FLAG.LOCK_KEYID | TCP_AUTHOPT_FLAG.LOCK_RNEXTKEYID,
            send_keyid=1,
            send_rnextkeyid=2,
        ),
    )
    with context as (client_socket, server_socket):
        check_socket_echo(client_socket)
        server_info = get_tcp_authopt(server_socket)
        client_info = get_tcp_authopt(client_socket)
        assert server_info.send_keyid == 2 and client_info.send_keyid == 1


def test_nosend_reject_send():
    """Server rejects switch to key2 which is marked nosend, it keeps sending with key1"""
    context = make_tcp_authopt_socket_pair(
        server_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111"),
            tcp_authopt_key(send_id=2, recv_id=2, key="222", nosend=True),
        ],
        client_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111"),
            tcp_authopt_key(send_id=2, recv_id=2, key="222"),
        ],
        client_authopt=tcp_authopt(
            flags=TCP_AUTHOPT_FLAG.LOCK_KEYID | TCP_AUTHOPT_FLAG.LOCK_RNEXTKEYID,
            send_keyid=1,
            send_rnextkeyid=2,
        ),
    )
    with context as (client_socket, server_socket):
        check_socket_echo(client_socket)
        server_info = get_tcp_authopt(server_socket)
        client_info = get_tcp_authopt(client_socket)
        assert (
            server_info.send_keyid == 1
            and server_info.recv_rnextkeyid == 2
            and client_info.recv_keyid == 1
        )


def test_nosend_norecv_reject():
    """Marking a key as NOSEND+NORECV rejects all incoming packets from the peer"""
    context = make_tcp_authopt_socket_pair(
        server_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111", nosend=True, norecv=True),
        ],
        client_key_list=[
            tcp_authopt_key(send_id=1, recv_id=1, key="111"),
        ],
    )
    with pytest.raises(OSError):
        with context:
            logger.info("unexpected success")
