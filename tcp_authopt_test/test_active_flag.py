import logging
from contextlib import ExitStack

import pytest
import waiting

from tcp_authopt_test.server import SimpleServerThread

from .linux_tcp_authopt import (
    TCP_AUTHOPT_FLAG,
    get_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt_key,
)
from .tcp_connection_fixture import TCPConnectionFixture

logger = logging.getLogger(__name__)


def wait_server_sock(server_thread: SimpleServerThread):
    def has_server_socket():
        return len(server_thread.server_socket) > 0

    waiting.wait(has_server_socket, sleep_seconds=0.1, timeout_seconds=5)


@pytest.mark.parametrize("addrbind", [True, False])
def test_active_on(exit_stack: ExitStack, addrbind: bool):
    con = TCPConnectionFixture(enable_sniffer=False)
    exit_stack.enter_context(con)
    client_socket = con.client_socket

    if addrbind:
        client_key_addr = con.server_addr
        server_key_addr = con.client_addr
    else:
        client_key_addr = None
        server_key_addr = None
    set_tcp_authopt_key(
        con.client_socket,
        tcp_authopt_key(send_id=1, recv_id=1, key=b"111", addr=client_key_addr),
    )
    set_tcp_authopt_key(
        con.listen_socket,
        tcp_authopt_key(send_id=1, recv_id=1, key=b"111", addr=server_key_addr),
    )

    client_socket.connect(con.server_addr_port)
    wait_server_sock(con.server_thread)
    server_socket = con.server_thread.server_socket[0]

    client_info = get_tcp_authopt(client_socket)
    assert client_info.flags & TCP_AUTHOPT_FLAG.ACTIVE != 0
    server_info = get_tcp_authopt(server_socket)
    assert server_info.flags & TCP_AUTHOPT_FLAG.ACTIVE != 0


def test_active_off(exit_stack: ExitStack):
    con = TCPConnectionFixture(enable_sniffer=False)
    exit_stack.enter_context(con)
    client_socket = con.client_socket

    set_tcp_authopt_key(
        con.client_socket,
        tcp_authopt_key(send_id=1, recv_id=1, key=b"111", addr="1.2.3.4"),
    )
    set_tcp_authopt_key(
        con.listen_socket,
        tcp_authopt_key(send_id=1, recv_id=1, key=b"111", addr="1.2.3.4"),
    )

    client_socket.connect(con.server_addr_port)
    wait_server_sock(con.server_thread)
    server_socket = con.server_thread.server_socket[0]
    client_info = get_tcp_authopt(client_socket)
    assert client_info.flags & TCP_AUTHOPT_FLAG.ACTIVE == 0
    server_info = get_tcp_authopt(server_socket)
    assert server_info.flags & TCP_AUTHOPT_FLAG.ACTIVE == 0
