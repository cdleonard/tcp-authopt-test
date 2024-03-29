# SPDX-License-Identifier: GPL-2.0
import os
import socket
import subprocess
from ipaddress import IPv4Address, IPv6Address
from tempfile import NamedTemporaryFile

from .conftest import raise_skip_no_netns
from .scapy_utils import IPvXAddress


class NamespaceFixture:
    """Create a pair of namespaces connected by one veth pair

    Each end of the pair has multiple addresses but everything is in the same subnet
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
    def client_netns_name(self):
        return self._get_name_prefix() + "_client"

    @classmethod
    def get_ipv4_addr(cls, ns=1, index=1) -> IPv4Address:
        return IPv4Address("10.10.0.0") + (ns << 8) + index

    @classmethod
    def get_ipv6_addr(cls, ns=1, index=1) -> IPv6Address:
        return IPv6Address("fd00::") + (ns << 16) + index

    @classmethod
    def get_addr(cls, address_family=socket.AF_INET, ns=1, index=1) -> IPvXAddress:
        if address_family == socket.AF_INET:
            return cls.get_ipv4_addr(ns, index)
        elif address_family == socket.AF_INET6:
            return cls.get_ipv6_addr(ns, index)
        else:
            raise ValueError(f"Bad address_family={address_family}")

    def get_server_addr(cls, address_family=socket.AF_INET, index=1) -> IPvXAddress:
        return cls.get_addr(ns=1, address_family=address_family, index=index)

    def get_client_addr(cls, address_family=socket.AF_INET, index=1) -> IPvXAddress:
        return cls.get_addr(ns=2, address_family=address_family, index=index)

    # 02:* means "locally administered"
    server_mac_addr = "02:00:00:00:00:01"
    client_mac_addr = "02:00:00:00:00:02"

    ipv4_prefix_len = 16
    ipv6_prefix_len = 64

    @classmethod
    def get_prefix_length(cls, address_family) -> int:
        return {
            socket.AF_INET: cls.ipv4_prefix_len,
            socket.AF_INET6: cls.ipv6_prefix_len,
        }[address_family]

    def __init__(self, **kw):
        raise_skip_no_netns()
        for k, v in kw.items():
            setattr(self, k, v)

    def __enter__(self):
        self._tmp = NamedTemporaryFile(prefix="tcp_authopt_test_")
        script = f"""
set -e
ip -b - <<IP
    netns add {self.server_netns_name}
    netns add {self.client_netns_name}
    link add veth0 netns {self.server_netns_name} type veth peer name veth0 netns {self.client_netns_name}
IP
"""
        client_script = f"link set veth0 up addr {self.client_mac_addr}\n"
        server_script = f"link set veth0 up addr {self.server_mac_addr}\n"
        for index in [1, 2, 3]:
            server_script += f"""
                addr add {self.get_ipv4_addr(1, index)}/16 dev veth0
                addr add {self.get_ipv6_addr(1, index)}/64 dev veth0 nodad
"""
            client_script += f"""
                addr add {self.get_ipv4_addr(2, index)}/16 dev veth0
                addr add {self.get_ipv6_addr(2, index)}/64 dev veth0 nodad
"""
        script += f"ip -n {self.server_netns_name} -b - <<IP\n{server_script}\nIP\n"
        script += f"ip -n {self.client_netns_name} -b - <<IP\n{client_script}\nIP\n"
        subprocess.run(script, shell=True, check=True)
        return self

    def _del_netns(self):
        if not self._tmp:
            return
        script = f"""\
set -e
ip netns del {self.server_netns_name} || true
ip netns del {self.client_netns_name} || true
"""
        subprocess.run(script, shell=True, check=True)
        self._tmp.close()
        self._tmp = None

    def __exit__(self, *a):
        self._del_netns()
