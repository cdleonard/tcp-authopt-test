import os
import socket
import subprocess
from contextlib import ExitStack
from ipaddress import IPv4Address, IPv6Address
from tempfile import NamedTemporaryFile

import pytest

from .conftest import raise_skip_no_netns


class TCPRepairNamespaceFixture:
    """Namespace fixture for testing TCP repair

    * Single server
    * Two clients that transfer TCP state between then
    * The two clients are in different namespaces with identical config
    * Middle namespace performs routing between server and client
    * Middle namespace has a bond device for the two clients, only one is active
    """

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
