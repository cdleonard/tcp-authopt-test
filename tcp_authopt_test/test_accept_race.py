import logging
import socket
from contextlib import ExitStack

import pytest
import waiting

from tcp_authopt_test.utils import check_socket_echo

from .linux_tcp_authopt import (
    TCP_AUTHOPT_FLAG,
    del_tcp_authopt_key,
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .tcp_connection_fixture import TCPConnectionFixture

logger = logging.getLogger(__name__)


@pytest.mark.xfail()
def test_accept_race(exit_stack: ExitStack):
    """Check what happens if key is deleted between connect and accept

    If keys are copied internally before accept then a functional server socket
    is created. This is the current behavior and it is wrong!
    """
    con = TCPConnectionFixture(enable_sniffer=False)
    server_thread = con.server_thread
    exit_stack.enter_context(con)
    listen_socket = con.listen_socket
    client_socket = con.client_socket

    set_tcp_authopt_key(
        listen_socket,
        tcp_authopt_key(send_id=1, recv_id=1, key=b"111"),
    )
    set_tcp_authopt_key(
        listen_socket,
        tcp_authopt_key(send_id=2, recv_id=2, key=b"222"),
    )
    set_tcp_authopt_key(
        client_socket,
        tcp_authopt_key(send_id=1, recv_id=1, key=b"111"),
    )
    set_tcp_authopt_key(
        client_socket,
        tcp_authopt_key(send_id=2, recv_id=2, key=b"222"),
    )
    set_tcp_authopt(
        client_socket,
        tcp_authopt(send_keyid=1, flags=TCP_AUTHOPT_FLAG.LOCK_KEYID),
    )

    def has_server_socket():
        return len(server_thread.server_socket) > 0

    server_thread.del_listen_socket(listen_socket)
    client_socket.connect(con.server_addr_port)

    del_tcp_authopt_key(listen_socket, tcp_authopt_key(send_id=1, recv_id=1))

    # Ensure that listen happens after key1 is deleted
    assert not has_server_socket()
    server_thread.add_listen_socket(listen_socket)
    waiting.wait(has_server_socket, sleep_seconds=0.1)

    # Should fail:
    with pytest.raises(socket.timeout):
        check_socket_echo(con.client_socket)
