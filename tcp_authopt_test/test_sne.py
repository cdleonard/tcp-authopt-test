# SPDX-License-Identifier: GPL-2.0
"""Validate SNE implementation for TCP-AO"""

import logging
from contextlib import ExitStack

from .tcp_connection_fixture import TCPConnectionFixture
from .utils import check_socket_echo

logger = logging.getLogger(__name__)


def test_sne(exit_stack: ExitStack):
    """Reproduce a seq/ack overlap"""
    overflow = 0x1000000
    bufsize = 0x10000
    con = TCPConnectionFixture(server_thread_kwargs=dict(bufsize=bufsize))
    exit_stack.enter_context(con)

    found = False

    client_socket = None
    for iter in range(1000):
        try:
            client_socket = con.create_client_socket()
            client_socket.connect(con.server_addr_port)
            client_isn, server_isn = con.sniffer_session.get_client_server_isn()
            logger.info(
                "iter %d client server ISN %08x %08x",
                iter,
                client_isn,
                server_isn,
            )

            if (
                client_isn + overflow > 0x100000000
                or server_isn + overflow > 0x100000000
            ):
                found = True
                break
            client_socket.close()
            con.sniffer_session.wait_close()
            con.sniffer_session.reset()
            client_socket = None
        finally:
            if not found and client_socket:
                client_socket.close()
    assert found

    for _ in range(2 * overflow // bufsize):
        check_socket_echo(client_socket, bufsize)
    con.sniffer_session.client_info.sisn
