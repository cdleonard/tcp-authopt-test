"""Test SOCK_DESTROY using ss --kill"""
import errno
import socket
import subprocess
from contextlib import ExitStack

import pytest

from .tcp_connection_fixture import TCPConnectionFixture
from .utils import check_socket_echo


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_estab(exit_stack: ExitStack, address_family):
    con = TCPConnectionFixture(address_family=address_family)
    exit_stack.enter_context(con)

    con.client_socket.connect(con.server_addr_port)
    check_socket_echo(con.client_socket)

    assert con.get_client_tcp_state() == "ESTAB"
    assert con.get_server_tcp_state() == "ESTAB"

    # Kill the server side of the connection
    script = f"ss --net {con.server_netns_name} --tcp --kill state all"
    subprocess.run(script, shell=True, check=True)
    assert con.get_server_tcp_state() == None
    with pytest.raises(socket.error) as e:
        check_socket_echo(con.client_socket)
    assert e.value.errno == errno.ECONNRESET
    con.server_thread.raise_exception_on_exit = False
