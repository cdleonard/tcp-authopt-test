import errno
import socket
import subprocess
from contextlib import ExitStack

import pytest

from .linux_tcp_authopt import TCP_AUTHOPT_ALG, tcp_authopt_key
from .tcp_connection_fixture import TCPConnectionFixture
from .utils import check_socket_echo


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test(exit_stack: ExitStack, address_family):
    """Manually sent a signed invalid packet after FIN and check TWSK signs RST correctly

    Kernel has a custom code path for this
    """
    key = tcp_authopt_key(
        alg=TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
        key=b"hello",
    )

    con = TCPConnectionFixture(
        address_family=address_family,
        tcp_authopt_key=key,
    )
    exit_stack.enter_context(con)

    # connect, transfer data and close client nicely
    con.client_socket.connect(con.server_addr_port)
    check_socket_echo(con.client_socket)

    subprocess.run(
        f"""
set -e -x
ss --net {con.client_netns_name} --numeric
ss --net {con.server_netns_name} --numeric
""",
        shell=True,
        check=True,
    )
    assert con.get_client_tcp_state() == "ESTAB"
    assert con.get_server_tcp_state() == "ESTAB"

    # Kill the server side of the connection
    subprocess.run(
        f"ss --net {con.server_netns_name} --tcp --kill", shell=True, check=True
    )
    assert con.get_server_tcp_state() == None
    with pytest.raises(socket.error) as e:
        check_socket_echo(con.client_socket)
    assert e.value.errno == errno.ECONNRESET
    con.server_thread.raise_exception_on_exit = False
