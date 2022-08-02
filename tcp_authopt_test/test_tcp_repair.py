import logging
import os
import socket
import subprocess
import time
import typing
from contextlib import ExitStack
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from tempfile import NamedTemporaryFile

from .conftest import parametrize_product
from .linux_tcp_authopt import set_tcp_authopt_key, tcp_authopt_key
from .linux_tcp_info import get_tcp_info, tcp_info
from .linux_tcp_repair_authopt import (
    get_tcp_repair_authopt,
    set_tcp_repair_authopt,
    tcp_repair_authopt,
)
from .scapy_utils import (
    AsyncSnifferContext,
    create_capture_socket,
    format_tcp_authopt_packet,
)

logger = logging.getLogger(__name__)

import pytest

from .conftest import raise_skip_no_netns
from .linux_tcp_repair import (
    TCP_REPAIR_QUEUE_ID,
    TCP_REPAIR_VAL,
    get_tcp_queue_seq,
    get_tcp_repair_window_buf,
    set_tcp_queue_seq,
    set_tcp_repair,
    set_tcp_repair_queue,
    set_tcp_repair_window_buf,
    set_tcp_repair_window_option,
    tcp_repair_window,
)
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_client_socket,
    create_listen_socket,
)


class TCPRepairNamespaceFixture:
    """Namespace fixture for testing TCP repair

    * Single server
    * Two clients that transfer TCP state between then
    * The two clients are in different namespaces with identical config
    * Middle namespace performs routing between server and client
    * Middle namespace has a bond device for the two clients, only one is active
    """

    _tmp = None

    def _get_name_prefix(self):
        if self._tmp is None:
            raise RuntimeError("not yet setup")
        return os.path.basename(self._tmp.name)

    @property
    def server_netns_name(self):
        return self._get_name_prefix() + "_server"

    @property
    def middle_netns_name(self):
        return self._get_name_prefix() + "_middle"

    @property
    def client1_netns_name(self):
        return self._get_name_prefix() + "_client1"

    @property
    def client2_netns_name(self):
        return self._get_name_prefix() + "_client2"

    # 02:* means "locally administered"
    server_veth0_mac_addr = "02:00:00:01:00:00"
    client1_mac_addr = "02:00:00:02:00:01"
    client2_mac_addr = "02:00:00:02:00:01"

    server_ipv4_addr = IPv4Address("10.10.1.1")
    client_ipv4_addr = IPv4Address("10.10.2.1")
    server_ipv6_addr = IPv6Address("fd00::1:1")
    client_ipv6_addr = IPv6Address("fd00::2:1")

    def __init__(self, **kw):
        raise_skip_no_netns()
        for k, v in kw.items():
            setattr(self, k, v)

    def __enter__(self):
        self._tmp = NamedTemporaryFile(prefix="tcp_authopt_test_")
        script = f"""
set -e
ip -batch - <<IP
    netns add {self.server_netns_name}
    netns add {self.middle_netns_name}
    netns add {self.client1_netns_name}
    netns add {self.client2_netns_name}
    link add veth0 netns {self.server_netns_name} type veth peer name veth0 netns {self.middle_netns_name}
    link add veth1 netns {self.middle_netns_name} type veth peer name veth0 netns {self.client1_netns_name}
    link add veth2 netns {self.middle_netns_name} type veth peer name veth0 netns {self.client2_netns_name}
IP
# Disable DAD everywhere
for ns in {self.server_netns_name} {self.middle_netns_name} {self.client1_netns_name} {self.client2_netns_name}; do
    ip netns exec $ns sysctl -qw \
net.ipv6.conf.all.accept_dad=0 \
net.ipv6.conf.default.accept_dad=0
done
ip -n {self.middle_netns_name} -batch - <<IP
    link add bond0 type bond mode active-backup
    link set veth1 master bond0
    link set veth2 master bond0
    addr add 10.10.1.3/24 dev veth0
    addr add 10.10.2.3/24 dev bond0
    addr add fd00::1:3/120 dev veth0 nodad
    addr add fd00::2:3/120 dev bond0 nodad
    link set veth1 up
    link set veth2 up
    link set bond0 up
    link set veth0 up
IP
ip -n {self.server_netns_name} -batch - <<IP
    link set veth0 addr {self.server_veth0_mac_addr}
    link set veth0 up
    addr add {self.server_ipv4_addr}/24 dev veth0
    addr add {self.server_ipv6_addr}/120 dev veth0 nodad
    route add 10.10.2.0/24 via 10.10.1.3
    route add fd00::2:0/120 via fd00::1:3
IP
ip -n {self.client1_netns_name} -batch - <<IP
    link set veth0 addr {self.client1_mac_addr}
    link set veth0 up
    addr add {self.client_ipv4_addr}/24 dev veth0
    addr add {self.client_ipv6_addr}/120 dev veth0 nodad
    route add 10.10.1.0/24 via 10.10.2.3
    route add fd00::1:0/120 via fd00::2:3
IP
ip -n {self.client2_netns_name} -batch - << IP
    link set veth0 addr {self.client2_mac_addr}
    link set veth0 up
    addr add {self.client_ipv4_addr}/24 dev veth0
    addr add {self.client_ipv6_addr}/120 dev veth0 nodad
    route add 10.10.1.0/24 via 10.10.2.3
    route add fd00::1:0/120 via fd00::2:3
IP
# Enable forwarding in middle
ip netns exec {self.middle_netns_name} sysctl -qw \
net.ipv4.ip_forward=1 \
net.ipv6.conf.all.forwarding=1
"""
        subprocess.run(script, shell=True, check=True)
        return self

    def set_active_client(self, index: int):
        if index != 1 and index != 2:
            raise ValueError(f"Bad index={index}")
        cmd = f"ip -n {self.middle_netns_name} link set bond0 type bond active_slave veth{index}"
        subprocess.run(cmd, shell=True, check=True)

    def _del_netns(self):
        if not self._tmp:
            return
        script = f"""\
set -e
for ns in {self.server_netns_name} {self.middle_netns_name} {self.client1_netns_name} {self.client2_netns_name}; do
    ip netns del "$ns" || true
done
"""
        subprocess.run(script, shell=True, check=True)
        self._tmp.close()
        self._tmp = None

    def __exit__(self, *a):
        self._del_netns()

    def get_client_addr(self, address_family):
        if address_family == socket.AF_INET:
            return self.client_ipv4_addr
        else:
            return self.client_ipv6_addr

    def get_server_addr(self, address_family):
        if address_family == socket.AF_INET:
            return self.server_ipv4_addr
        else:
            return self.server_ipv6_addr


def init_debug_sniffer(exit_stack: ExitStack, nsfixture: TCPRepairNamespaceFixture):
    return exit_stack.enter_context(
        AsyncSnifferContext(
            opened_socket=create_capture_socket(
                ns=nsfixture.server_netns_name,
                iface="veth0",
                filter="tcp",
            ),
            prn=lambda p: logger.info(
                "sniff %s", format_tcp_authopt_packet(p, include_seq=True)
            ),
        )
    )


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_bond_switch(exit_stack: ExitStack, address_family):
    """Verify bond switching via ping"""
    nsfixture = exit_stack.enter_context(TCPRepairNamespaceFixture())
    server_addr = nsfixture.get_server_addr(address_family)
    client_addr = nsfixture.get_client_addr(address_family)

    cmd_ping_from_client1 = (
        f"ip netns exec {nsfixture.client1_netns_name} ping -w1 -c1 {server_addr}"
    )
    cmd_ping_from_client2 = (
        f"ip netns exec {nsfixture.client2_netns_name} ping -w1 -c1 {server_addr}"
    )
    cmd_ping_from_server = (
        f"ip netns exec {nsfixture.server_netns_name} ping -w1 -c1 {client_addr}"
    )
    assert 0 == subprocess.call(cmd_ping_from_server, shell=True)
    assert 0 == subprocess.call(cmd_ping_from_client1, shell=True)
    assert 0 != subprocess.call(cmd_ping_from_client2, shell=True)
    nsfixture.set_active_client(2)
    assert 0 == subprocess.call(cmd_ping_from_server, shell=True)
    assert 0 != subprocess.call(cmd_ping_from_client1, shell=True)
    assert 0 == subprocess.call(cmd_ping_from_client2, shell=True)
    nsfixture.set_active_client(1)
    assert 0 == subprocess.call(cmd_ping_from_server, shell=True)
    assert 0 == subprocess.call(cmd_ping_from_client1, shell=True)
    assert 0 != subprocess.call(cmd_ping_from_client2, shell=True)


@dataclass(init=False)
class TCPRepairData:
    """Wrapper around TCP repair fields to transfer from one sock to another"""

    recv_queue_seq: int
    send_queue_seq: int
    window_buf: bytes
    tcp_info: tcp_info
    authopt_info: typing.Optional[tcp_repair_authopt]

    def get(self, sock: socket.socket, ao: bool = False):
        set_tcp_repair_queue(sock, TCP_REPAIR_QUEUE_ID.RECV_QUEUE)
        self.recv_queue_seq = get_tcp_queue_seq(sock)
        set_tcp_repair_queue(sock, TCP_REPAIR_QUEUE_ID.SEND_QUEUE)
        self.send_queue_seq = get_tcp_queue_seq(sock)
        self.tcp_info = get_tcp_info(sock)
        self.window_buf = get_tcp_repair_window_buf(sock)
        if ao:
            self.authopt_info = get_tcp_repair_authopt(sock)
        else:
            self.authopt_info = None

    def set(self, sock: socket.socket):
        set_tcp_repair_queue(sock, TCP_REPAIR_QUEUE_ID.RECV_QUEUE)
        set_tcp_queue_seq(sock, self.recv_queue_seq)
        set_tcp_repair_queue(sock, TCP_REPAIR_QUEUE_ID.SEND_QUEUE)
        set_tcp_queue_seq(sock, self.send_queue_seq)
        if self.authopt_info is not None:
            set_tcp_repair_authopt(sock, self.authopt_info)

    def set_estab(self, sock: socket.socket):
        set_tcp_repair_window_buf(sock, self.window_buf)
        wscale_ok = (self.tcp_info.tcpi_options & 4) != 0
        if wscale_ok:
            set_tcp_repair_window_option(
                sock,
                self.tcp_info.tcpi_rcv_wscale,
                self.tcp_info.tcpi_snd_wscale,
            )


@parametrize_product(
    address_family=(socket.AF_INET, socket.AF_INET6),
    ao=(False, True),
)
def test_tcp_repair(exit_stack: ExitStack, address_family, ao: bool):
    nsfixture = exit_stack.enter_context(TCPRepairNamespaceFixture())
    server_addr = nsfixture.get_server_addr(address_family)
    client_addr = nsfixture.get_client_addr(address_family)
    server_addrport = (str(server_addr), DEFAULT_TCP_SERVER_PORT)
    client_port = 27972

    # create server:
    listen_socket = exit_stack.push(
        create_listen_socket(
            family=address_family,
            ns=nsfixture.server_netns_name,
        )
    )
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    # create client socket:
    client1_socket = create_client_socket(
        ns=nsfixture.client1_netns_name,
        bind_port=client_port,
        family=address_family,
    )
    client2_socket = create_client_socket(
        ns=nsfixture.client2_netns_name,
        bind_port=client_port,
        family=address_family,
    )
    if ao:
        set_tcp_authopt_key(listen_socket, tcp_authopt_key(key="aaa", addr=client_addr))
        set_tcp_authopt_key(
            client1_socket, tcp_authopt_key(key="aaa", addr=server_addr)
        )
        set_tcp_authopt_key(
            client2_socket, tcp_authopt_key(key="aaa", addr=server_addr)
        )

    # Suffers from some sort of DAD issue:
    if address_family == socket.AF_INET6:
        time.sleep(2)
    client1_socket.connect(server_addrport)
    check_socket_echo(client1_socket)

    client_repair_data = TCPRepairData()
    set_tcp_repair(client1_socket, TCP_REPAIR_VAL.ON)
    client_repair_data.get(client1_socket, ao=ao)
    # client1 is kept in the repair state

    set_tcp_repair(client2_socket, TCP_REPAIR_VAL.ON)
    client_repair_data.set(client2_socket)
    client2_socket.connect(server_addrport)
    client_repair_data.set_estab(client2_socket)

    # Switch and release from the repair state:
    nsfixture.set_active_client(2)
    set_tcp_repair(client2_socket, TCP_REPAIR_VAL.OFF_NO_WP)

    check_socket_echo(client2_socket)


def init_tcp_repair_sock_pair(
    exit_stack: ExitStack,
    nsfixture: TCPRepairNamespaceFixture,
    address_family: socket.AddressFamily = socket.AF_INET,
    client_isn: int = 0x11111111,
    server_isn: int = 0x22222222,
) -> typing.Tuple[socket.socket, socket.socket]:
    server_addr = nsfixture.get_server_addr(address_family)
    client_addr = nsfixture.get_client_addr(address_family)
    client_port = 27272
    server_port = 17271
    server_addrport = (str(server_addr), server_port)
    client_addrport = (str(client_addr), client_port)

    # create synthetic server socket
    server_socket = exit_stack.push(
        create_client_socket(
            ns=nsfixture.server_netns_name,
            family=address_family,
            bind_addr=server_addr,
            bind_port=server_port,
        )
    )
    client_socket = exit_stack.push(
        create_client_socket(
            ns=nsfixture.client1_netns_name,
            family=address_family,
            bind_addr=client_addr,
            bind_port=client_port,
        )
    )

    set_tcp_repair(client_socket, TCP_REPAIR_VAL.ON)
    set_tcp_repair_queue(client_socket, TCP_REPAIR_QUEUE_ID.RECV_QUEUE)
    set_tcp_queue_seq(client_socket, server_isn)
    set_tcp_repair_queue(client_socket, TCP_REPAIR_QUEUE_ID.SEND_QUEUE)
    set_tcp_queue_seq(client_socket, client_isn)
    set_tcp_repair(server_socket, TCP_REPAIR_VAL.ON)
    set_tcp_repair_queue(server_socket, TCP_REPAIR_QUEUE_ID.RECV_QUEUE)
    set_tcp_queue_seq(server_socket, client_isn)
    set_tcp_repair_queue(server_socket, TCP_REPAIR_QUEUE_ID.SEND_QUEUE)
    set_tcp_queue_seq(server_socket, server_isn)

    client_socket.connect(server_addrport)
    server_socket.connect(client_addrport)

    return client_socket, server_socket


def test_tcp_repair_both_sides(exit_stack: ExitStack):
    """Create a TCP connection without SYN, just using TCP_REPAIR on both sides"""
    address_family = socket.AF_INET
    nsfixture = exit_stack.enter_context(TCPRepairNamespaceFixture())
    server_thread = exit_stack.enter_context(SimpleServerThread(mode="echo"))
    init_debug_sniffer(exit_stack, nsfixture)
    client_socket, server_socket = init_tcp_repair_sock_pair(
        exit_stack,
        nsfixture,
        address_family,
    )

    server_thread._register_server_socket(server_socket)
    set_tcp_repair(client_socket, TCP_REPAIR_VAL.OFF)
    set_tcp_repair(server_socket, TCP_REPAIR_VAL.OFF)

    # Check traffic works
    # Use very small packet because of lack of window initialization
    size = 128
    check_socket_echo(client_socket, size=size)
    check_socket_echo(client_socket, size=size)


def test_tcp_repair_before_sne_rollver(exit_stack: ExitStack):
    """Test TCP_REPAIR with a sequence number that causes quick SNE rollover"""
    address_family = socket.AF_INET
    nsfixture = exit_stack.enter_context(TCPRepairNamespaceFixture())
    server_addr = nsfixture.get_server_addr(address_family)
    client_addr = nsfixture.get_client_addr(address_family)
    server_thread = exit_stack.enter_context(SimpleServerThread(mode="echo"))
    init_debug_sniffer(exit_stack, nsfixture)
    client_socket, server_socket = init_tcp_repair_sock_pair(
        exit_stack,
        nsfixture,
        address_family,
        client_isn=0xFFFFFF00,
        server_isn=0x10000000,
    )

    set_tcp_authopt_key(client_socket, tcp_authopt_key(key="aaa", addr=server_addr))
    set_tcp_authopt_key(server_socket, tcp_authopt_key(key="aaa", addr=client_addr))
    server_thread._register_server_socket(server_socket)
    set_tcp_repair(client_socket, TCP_REPAIR_VAL.OFF)
    set_tcp_repair(server_socket, TCP_REPAIR_VAL.OFF)

    size = 128
    check_socket_echo(client_socket, size=size)
    check_socket_echo(client_socket, size=size)
    check_socket_echo(client_socket, size=size)

    client_authopt_repair_info = get_tcp_repair_authopt(client_socket)
    assert client_authopt_repair_info.snd_sne == 1
    server_authopt_repair_info = get_tcp_repair_authopt(server_socket)
    assert server_authopt_repair_info.rcv_sne == 1
