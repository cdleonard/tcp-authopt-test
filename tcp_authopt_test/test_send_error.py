"""
If no valid keys are found then an error should be reported on connect or send.
"""

import subprocess
from contextlib import ExitStack

import pytest
from scapy.layers.inet import TCP
from scapy.packet import Packet
from scapy.plist import PacketList

from tcp_authopt_test.scapy_utils import scapy_tcp_get_authopt_val
from tcp_authopt_test.utils import check_socket_echo

from .linux_tcp_authopt import (
    TCP_AUTHOPT_KEY_FLAG,
    del_tcp_authopt_key,
    set_tcp_authopt_key,
    tcp_authopt_key,
)
from .tcp_connection_fixture import TCPConnectionFixture


@pytest.mark.xfail
def test_connect(exit_stack: ExitStack):
    master_key = b"123"
    con = TCPConnectionFixture()
    exit_stack.enter_context(con)
    sniffer = con.sniffer

    client_key = tcp_authopt_key(key=master_key, nosend=True)
    server_key = tcp_authopt_key(key=master_key)
    set_tcp_authopt_key(con.client_socket, client_key)
    set_tcp_authopt_key(con.listen_socket, server_key)

    with pytest.raises(Exception):
        con.client_socket.connect(con.server_addr_port)

    sniffer.stop()

    def is_tcp_syn(p: Packet) -> bool:
        return p[TCP] and p[TCP].flags.S

    assert not any(is_tcp_syn(p) for p in sniffer.results)


@pytest.mark.xfail
def test_client_key_expires(exit_stack: ExitStack):
    master_key = b"123"
    con = TCPConnectionFixture()
    exit_stack.enter_context(con)
    sniffer = con.sniffer

    client_key = tcp_authopt_key(key=master_key)
    server_key = tcp_authopt_key(key=master_key)
    set_tcp_authopt_key(con.client_socket, client_key)
    set_tcp_authopt_key(con.listen_socket, server_key)

    con.client_socket.connect(con.server_addr_port)
    check_socket_echo(con.client_socket)
    client_key.nosend = True
    set_tcp_authopt_key(con.client_socket, client_key)
    with pytest.raises(Exception):
        check_socket_echo(con.client_socket)

    con.sniffer.stop()
    assert_all_packets_have_ao(sniffer.results)


@pytest.mark.xfail
def test_server_key_badaddr(exit_stack: ExitStack):
    """Server has two keys and the matching one is deleted"""
    master_key = b"123"
    con = TCPConnectionFixture()
    exit_stack.enter_context(con)
    sniffer = con.sniffer

    client_key = tcp_authopt_key(key=master_key, send_id=1, recv_id=1)
    client_addr = con.client_addr
    client_addr2 = con.client_addr + 1
    server_key1 = tcp_authopt_key(
        key=master_key, addr=client_addr, send_id=1, recv_id=1
    )
    server_key2 = tcp_authopt_key(
        key=master_key, addr=client_addr2, send_id=2, recv_id=2
    )
    assert server_key1.get_real_flags() & TCP_AUTHOPT_KEY_FLAG.BIND_ADDR != 0
    assert server_key2.get_real_flags() & TCP_AUTHOPT_KEY_FLAG.BIND_ADDR != 0
    set_tcp_authopt_key(con.client_socket, client_key)
    set_tcp_authopt_key(con.listen_socket, server_key1)
    set_tcp_authopt_key(con.listen_socket, server_key2)

    con.client_socket.connect(con.server_addr_port)
    check_socket_echo(con.client_socket)

    table = subprocess.check_output(
        f"ip netns exec {con.server_netns_name} cat /proc/net/tcp_authopt",
        shell=True,
        text=True,
    )
    assert str(client_addr) in table
    assert str(client_addr2) in table
    del_tcp_authopt_key(con.listen_socket, server_key1)
    table = subprocess.check_output(
        f"ip netns exec {con.server_netns_name} cat /proc/net/tcp_authopt",
        shell=True,
        text=True,
    )
    assert str(client_addr) not in table
    assert str(client_addr2) in table

    with pytest.raises(Exception):
        check_socket_echo(con.client_socket)

    con.sniffer.stop()
    assert_all_packets_have_ao(sniffer.results)


def assert_all_packets_have_ao(plist: PacketList):
    # check all packets on the wire have sensible AO options
    for p in plist:
        th = p[TCP]
        if not th:
            continue
        ao = scapy_tcp_get_authopt_val(p[TCP])
        if ao:
            assert ao.mac != b"\0" * 16
        else:
            assert False, "Found packet without AO option"
