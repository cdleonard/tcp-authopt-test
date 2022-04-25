"""
If no valid keys are found then an error should be reported on connect or send.
"""

import errno
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


pytestmark = pytest.mark.xfail


def test_connect(exit_stack: ExitStack):
    """Test connect() with an expired key

    It should return an error without sending any packets.
    """
    master_key = b"123"
    con = TCPConnectionFixture()
    exit_stack.enter_context(con)
    sniffer = con.sniffer

    client_key = tcp_authopt_key(key=master_key, nosend=True)
    server_key = tcp_authopt_key(key=master_key)
    set_tcp_authopt_key(con.client_socket, client_key)
    set_tcp_authopt_key(con.listen_socket, server_key)

    with pytest.raises(IOError) as ei:
        con.client_socket.connect(con.server_addr_port)
    assert ei.type == IOError
    assert ei.value.errno == errno.ENOKEY

    sniffer.stop()

    def is_tcp_syn(p: Packet) -> bool:
        return p[TCP] and p[TCP].flags.S

    assert not any(is_tcp_syn(p) for p in sniffer.results)


def test_client_key_expires(exit_stack: ExitStack):
    """Test key expires after succesful client connect

    It should return an error without sending any additional packets.
    """
    master_key = b"123"
    con = TCPConnectionFixture()
    exit_stack.enter_context(con)
    sniffer = con.sniffer

    client_key = tcp_authopt_key(key=master_key)
    server_key = tcp_authopt_key(key=master_key)
    set_tcp_authopt_key(con.client_socket, client_key)
    set_tcp_authopt_key(con.listen_socket, server_key)

    # Establish connection and check traffic works
    con.client_socket.connect(con.server_addr_port)
    check_socket_echo(con.client_socket)

    # Mark the key as "nosend/expired"
    client_key.nosend = True
    set_tcp_authopt_key(con.client_socket, client_key)

    # Check sending again results in an error
    with pytest.raises(IOError) as ei:
        check_socket_echo(con.client_socket, 10, checked=True)
    assert ei.type == IOError
    assert ei.value.errno == errno.ENOKEY

    con.sniffer.stop()
    assert_all_packets_have_ao(sniffer.results)


def test_server_key_expires(exit_stack: ExitStack):
    """Test key expires after succesful server accept

    It should return an error without sending any additional packets.

    Unlike the client test an additional key for a different destination is also present.
    """
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

    server_key1.nosend = True
    set_tcp_authopt_key(con.listen_socket, server_key1)

    table = subprocess.check_output(
        f"ip netns exec {con.server_netns_name} cat /proc/net/tcp_authopt",
        shell=True,
        text=True,
    )
    assert str(client_addr) in table
    assert str(client_addr2) in table

    with pytest.raises(Exception):
        check_socket_echo(con.client_socket)
        check_socket_echo(con.client_socket)
        check_socket_echo(con.client_socket)

    con.sniffer.stop()
    assert_all_packets_have_ao(sniffer.results)
    # Check server received IOError ENOKEY specifically
    con.server_thread.raise_exception_on_exit = False
    con.server_thread.stop()
    assert type(con.server_thread.exception) == IOError
    assert con.server_thread.exception.errno == errno.ENOKEY


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
