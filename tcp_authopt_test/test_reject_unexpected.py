# SPDX-License-Identifier: GPL-2.0
import logging
import socket
from contextlib import ExitStack

import pytest
from scapy.layers.inet import TCP

from .conftest import skipif_missing_tcp_authopt
from .linux_tcp_authopt import (
    TCP_AUTHOPT_FLAG,
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .scapy_utils import scapy_tcp_get_authopt_val
from .tcp_connection_fixture import TCPConnectionFixture

pytestmark = skipif_missing_tcp_authopt
logger = logging.getLogger(__name__)


def test_accept_unexpected(exit_stack: ExitStack):
    con = exit_stack.enter_context(TCPConnectionFixture())
    set_tcp_authopt_key(
        con.client_socket,
        tcp_authopt_key(send_id=1, recv_id=1, key="111", addr=con.server_addr),
    )
    set_tcp_authopt_key(
        con.listen_socket,
        tcp_authopt_key(send_id=2, recv_id=2, key="222", addr=con.client_addr + 10),
    )

    # Connect can only fail because server doesn't have the right key
    # By default the server will accept unexpected AO and reply with an unsigned SYNACK
    # With REJECT_UNEXPECTED the server won't even send a SYNACK
    with pytest.raises(socket.timeout):
        con.client_socket.connect(con.server_addr_port)

    con.sniffer.stop()

    found_syn = False
    found_synack = False
    for p in con.sniffer.results:
        if p[TCP] and p[TCP].flags.S and not p[TCP].flags.A:
            assert scapy_tcp_get_authopt_val(p[TCP])
            found_syn = True
        if p[TCP] and p[TCP].flags.S and p[TCP].flags.A:
            assert not scapy_tcp_get_authopt_val(p[TCP])
            found_synack = True

    assert found_syn
    assert found_synack


def test_reject_unexpected(exit_stack: ExitStack):
    con = exit_stack.enter_context(TCPConnectionFixture())
    set_tcp_authopt_key(
        con.client_socket,
        tcp_authopt_key(send_id=1, recv_id=1, key="111", addr=con.server_addr),
    )
    set_tcp_authopt_key(
        con.listen_socket,
        tcp_authopt_key(send_id=2, recv_id=2, key="222", addr=con.client_addr + 10),
    )
    set_tcp_authopt(
        con.listen_socket, tcp_authopt(flags=TCP_AUTHOPT_FLAG.REJECT_UNEXPECTED)
    )

    # Connect can only fail because server doesn't have the right key
    # With REJECT_UNEXPECTED the server won't even send a SYNACK
    with pytest.raises(socket.timeout):
        con.client_socket.connect(con.server_addr_port)

    con.sniffer.stop()

    found_syn = False
    found_synack = False
    for p in con.sniffer.results:
        if p[TCP] and p[TCP].flags.S and not p[TCP].flags.A:
            assert scapy_tcp_get_authopt_val(p[TCP])
            found_syn = True
        if p[TCP] and p[TCP].flags.S and p[TCP].flags.A:
            found_synack = True

    assert found_syn
    assert not found_synack
