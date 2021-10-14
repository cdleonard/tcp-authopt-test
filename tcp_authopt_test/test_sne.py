# SPDX-License-Identifier: GPL-2.0
"""Validate SNE implementation for TCP-AO"""

import logging
import socket
from contextlib import ExitStack

import pytest

from .linux_tcp_authopt import set_tcp_authopt_key_kwargs
from .linux_tcp_repair import get_tcp_repair_recv_send_queue_seq, tcp_repair_toggle
from .linux_tcp_repair_authopt import get_tcp_repair_authopt
from .netns_fixture import NamespaceFixture
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_client_socket,
    create_listen_socket,
    socket_set_linger,
)

logger = logging.getLogger(__name__)


@pytest.mark.parametrize("signed", [False, True])
def test_sne(exit_stack: ExitStack, signed: bool):
    """Reproduce a seq/ack overlap"""
    overflow = 0x200000
    bufsize = 0x10000
    secret_key = b"12345"
    mode = "recv"
    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = nsfixture.get_addr(socket.AF_INET, 1)
    client_addr = nsfixture.get_addr(socket.AF_INET, 2)
    server_addr_port = (str(server_addr), DEFAULT_TCP_SERVER_PORT)
    listen_socket = create_listen_socket(
        ns=nsfixture.server_netns_name,
        bind_addr=server_addr,
    )
    exit_stack.enter_context(listen_socket)
    if signed:
        set_tcp_authopt_key_kwargs(listen_socket, key=secret_key)
    server_thread = SimpleServerThread(listen_socket, mode=mode, bufsize=bufsize)
    exit_stack.enter_context(server_thread)

    found = False

    client_socket = None
    for _ in range(10000):
        try:
            client_socket = create_client_socket(
                ns=nsfixture.client_netns_name,
                bind_addr=client_addr,
            )
            if signed:
                set_tcp_authopt_key_kwargs(client_socket, key=secret_key)
            client_socket.connect(server_addr_port)

            recv_seq, send_seq = get_tcp_repair_recv_send_queue_seq(client_socket)
            if (recv_seq + overflow > 0x100000000 and mode == "echo") or (
                send_seq + overflow > 0x100000000
            ):
                found = True
                break
            socket_set_linger(client_socket, 1, 0)
            client_socket.close()
            client_socket = None
        finally:
            if not found and client_socket:
                client_socket.close()
    assert found

    logger.debug("setup recv_seq %08x send_seq %08x", recv_seq, send_seq)

    if signed:
        with tcp_repair_toggle(client_socket):
            init_tcp_repair_authopt = get_tcp_repair_authopt(client_socket)
        assert init_tcp_repair_authopt.src_isn + 1 == send_seq
        assert init_tcp_repair_authopt.dst_isn + 1 == recv_seq
        assert init_tcp_repair_authopt.snd_sne == 0
        assert init_tcp_repair_authopt.rcv_sne == 0
        logger.debug("tcp repair authopt: %r", init_tcp_repair_authopt)

    logger.info("transfer %d bytes", 2 * overflow)
    for _ in range(2 * overflow // bufsize):
        if mode == "recv":
            from .utils import randbytes

            send_buf = randbytes(bufsize)
            client_socket.sendall(send_buf)
        else:
            check_socket_echo(client_socket, bufsize)

    new_recv_seq, new_send_seq = get_tcp_repair_recv_send_queue_seq(client_socket)
    logger.debug("final recv_seq %08x send_seq %08x", new_recv_seq, new_send_seq)

    if signed:
        with tcp_repair_toggle(client_socket):
            exit_tcp_repair_authopt = get_tcp_repair_authopt(client_socket)
        logger.debug("exit tcp repair authopt: %r", exit_tcp_repair_authopt)
        assert exit_tcp_repair_authopt.src_isn == init_tcp_repair_authopt.src_isn
        assert exit_tcp_repair_authopt.dst_isn == init_tcp_repair_authopt.dst_isn
        assert (
            exit_tcp_repair_authopt.snd_sne != 0 or exit_tcp_repair_authopt.rcv_sne != 0
        )

    assert new_recv_seq < recv_seq or new_send_seq < send_seq
