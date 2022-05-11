import logging
import subprocess
from contextlib import ExitStack

import pytest
import waiting

from .tcp_connection_fixture import TCPConnectionFixture
from .utils import check_socket_echo, create_listen_socket

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("iter", list(range(8)))
def test_timewait(exit_stack: ExitStack, iter):
    """Investigate TCPConnectionFixture.get_client_sock_state reporting duplicates"""
    con = TCPConnectionFixture(enable_sniffer=False)
    con.server_port = 10000 + iter
    con.client_bind_port = 20000 + iter
    exit_stack.enter_context(con)

    # One listen and one not-yet-connected client socket
    client_sock_state = subprocess.check_output(
        f"ss --net {con.client_netns_name} --extended --tcp --no-header --numeric state all",
        shell=True,
        text=True,
    )
    server_sock_state = subprocess.check_output(
        f"ss --net {con.server_netns_name} --extended --tcp --no-header --numeric state all",
        shell=True,
        text=True,
    )
    assert len(server_sock_state.splitlines()) == 1
    if len(client_sock_state.splitlines()) != 0:
        logger.error(
            "Unexpected sockets in fresh namespace iter=%d:\n%s",
            iter,
            client_sock_state,
        )
        assert False
    assert len(client_sock_state.splitlines()) == 0

    # connect, transfer data and check both are ESTABLISHED
    con.client_socket.connect(con.server_addr_port)
    check_socket_echo(con.client_socket)
    assert con.get_client_tcp_state() == "ESTAB"
    assert con.get_server_tcp_state() == "ESTAB"

    # Close nicely and check for TIME-WAIT
    con.client_socket.close()

    def check():
        cs = con.get_client_tcp_state()
        ss = con.get_server_tcp_state()
        logging.info("client tcp state %r server tcp state %r", cs, ss)
        return ss is None and cs == "TIME-WAIT"

    waiting.wait(check, timeout_seconds=5, sleep_seconds=0.1)


def test_listen():
    """Try to make listen sockets get reused"""
    with ExitStack() as exit_stack:
        logger.info("LOOP INIT")
        for iter in range(8):
            from .netns_fixture import NamespaceFixture

            with NamespaceFixture() as nsfix:
                sock = create_listen_socket(
                    nsfix.server_netns_name,
                    bind_port=10000 + iter,
                )
                exit_stack.enter_context(sock)
                server_sock_state = subprocess.check_output(
                    f"ss --net {nsfix.server_netns_name} --extended --tcp --no-header --numeric state listening",
                    shell=True,
                    text=True,
                )
                assert len(server_sock_state.splitlines()) == 1
        logger.info("LOOP DONE")
