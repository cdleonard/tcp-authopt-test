import subprocess
from contextlib import ExitStack

import pytest
import waiting

from .tcp_connection_fixture import TCPConnectionFixture
from .utils import check_socket_echo


@pytest.mark.parametrize("iter", list(range(10)))
def test(exit_stack: ExitStack, iter):
    """Investigate TCPConnectionFixture.get_client_sock_state reporting duplicates"""
    con = TCPConnectionFixture()
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

    con.client_socket.close()

    def check():
        return (
            con.get_client_tcp_state() is None
            and con.get_server_tcp_state() == "TIME-WAIT"
        )

    waiting.wait(check, timeout_seconds=1, interval=0.1)
