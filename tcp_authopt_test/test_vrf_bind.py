"""Test VRF overlap behavior

With tcp_l3mdev_accept single server should be able to differentiate multiple
clients with same IP coming from different VRFs.
"""
import pytest
from contextlib import ExitStack
import socket

from .utils import (
    create_listen_socket,
    create_client_socket,
    check_socket_echo,
    DEFAULT_TCP_SERVER_PORT,
)
from .conftest import skipif_missing_tcp_authopt
from .server import SimpleServerThread
from .vrf_netns_fixture import VrfNamespaceFixture
from .linux_tcp_authopt import set_tcp_authopt_key, tcp_authopt_key
from . import linux_tcp_authopt
from . import linux_tcp_md5sig


class VrfFixture:
    """Fixture for VRF testing

    Single server has two interfaces with same IP addr: one inside VRF and one
    outside. Two clients two namespaces have same client IP, one connected to
    VRF and one outside.
    """

    def __init__(self, address_family=socket.AF_INET):
        self.address_family = address_family

    @property
    def server_addr(self):
        if self.address_family == socket.AF_INET:
            return self.nsfixture.server_ipv4_addr
        else:
            return self.nsfixture.server_ipv6_addr

    @property
    def client_addr(self):
        if self.address_family == socket.AF_INET:
            return self.nsfixture.client_ipv4_addr
        else:
            return self.nsfixture.client_ipv6_addr

    @property
    def server_addr_port(self):
        return (str(self.server_addr), DEFAULT_TCP_SERVER_PORT)

    def create_listen_socket(self):
        return create_listen_socket(
            family=self.address_family,
            ns=self.nsfixture.server_netns_name,
            bind_addr=self.server_addr,
        )

    def create_client_socket(self, ns):
        result = create_client_socket(
            ns=ns, family=self.address_family, bind_addr=self.client_addr
        )
        self.exit_stack.enter_context(result)
        return result

    def __enter__(self):
        self.exit_stack = ExitStack()
        self.exit_stack.__enter__()
        self.nsfixture = self.exit_stack.enter_context(VrfNamespaceFixture())

        self.listen_socket = self.create_listen_socket()
        self.exit_stack.enter_context(self.listen_socket)
        self.server_thread = SimpleServerThread(self.listen_socket, mode="echo")
        self.exit_stack.enter_context(self.server_thread)

    def __exit__(self, *args):
        self.exit_stack.__exit__(*args)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_vrf_overlap_unsigned(exit_stack: ExitStack, address_family):
    """Test without any signature support"""
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)

    client_socket0 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    exit_stack.enter_context(client_socket0)
    client_socket1 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    exit_stack.enter_context(client_socket1)
    client_socket2 = fix.create_client_socket(fix.nsfixture.client2_netns_name)
    exit_stack.enter_context(client_socket2)

    client_socket2.connect(fix.server_addr_port)
    client_socket1.connect(fix.server_addr_port)
    client_socket0.connect(fix.server_addr_port)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)
    check_socket_echo(client_socket0)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)
    check_socket_echo(client_socket0)
    check_socket_echo(client_socket2)


def set_server_md5_key0(fix, key=b"000"):
    linux_tcp_md5sig.setsockopt_md5sig_kwargs(
        fix.listen_socket, key=key, addr=fix.client_addr
    )


def set_server_md5_key1(fix, key=b"111"):
    linux_tcp_md5sig.setsockopt_md5sig_kwargs(
        fix.listen_socket,
        key=key,
        ifindex=fix.nsfixture.server_vrf1_ifindex,
        addr=fix.client_addr,
    )


def set_server_md5_key2(fix, key=b"222"):
    linux_tcp_md5sig.setsockopt_md5sig_kwargs(
        fix.listen_socket,
        key=key,
        ifindex=fix.nsfixture.server_vrf2_ifindex,
        addr=fix.client_addr,
    )


def set_client_md5_key(fix, client_socket, key):
    linux_tcp_md5sig.setsockopt_md5sig_kwargs(
        client_socket, key=key, addr=fix.server_addr
    )


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_vrf_overlap_md5_samekey(exit_stack: ExitStack, address_family):
    """Test overlapping keys that are identical"""
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)
    set_server_md5_key0(fix, b"same")
    set_server_md5_key1(fix, b"same")
    set_server_md5_key2(fix, b"same")
    client_socket0 = fix.create_client_socket(fix.nsfixture.client0_netns_name)
    client_socket1 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    client_socket2 = fix.create_client_socket(fix.nsfixture.client2_netns_name)
    set_client_md5_key(fix, client_socket0, b"same")
    set_client_md5_key(fix, client_socket1, b"same")
    set_client_md5_key(fix, client_socket2, b"same")
    client_socket0.connect(fix.server_addr_port)
    client_socket1.connect(fix.server_addr_port)
    client_socket2.connect(fix.server_addr_port)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)
    check_socket_echo(client_socket0)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_vrf_overlap12_md5(exit_stack: ExitStack, address_family):
    """Test overlapping keys between vrfs"""
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)
    set_server_md5_key1(fix)
    set_server_md5_key2(fix)
    client_socket1 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    client_socket2 = fix.create_client_socket(fix.nsfixture.client2_netns_name)
    set_client_md5_key(fix, client_socket1, b"111")
    set_client_md5_key(fix, client_socket2, b"222")
    client_socket1.connect(fix.server_addr_port)
    client_socket2.connect(fix.server_addr_port)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_vrf_overlap01_md5(exit_stack: ExitStack, address_family):
    """Test overlapping keys inside and outside vrf, VRF key added second"""
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)
    set_server_md5_key0(fix)
    set_server_md5_key1(fix)
    client_socket0 = fix.create_client_socket(fix.nsfixture.client0_netns_name)
    client_socket1 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    set_client_md5_key(fix, client_socket0, b"000")
    set_client_md5_key(fix, client_socket1, b"111")
    client_socket1.connect(fix.server_addr_port)
    client_socket0.connect(fix.server_addr_port)
    check_socket_echo(client_socket0)
    check_socket_echo(client_socket1)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_vrf_overlap10_md5(exit_stack: ExitStack, address_family):
    """Test overlapping keys inside and outside vrf, VRF key added first"""
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)
    set_server_md5_key1(fix)
    set_server_md5_key0(fix)
    client_socket0 = fix.create_client_socket(fix.nsfixture.client0_netns_name)
    client_socket1 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    set_client_md5_key(fix, client_socket0, b"000")
    set_client_md5_key(fix, client_socket1, b"111")
    client_socket1.connect(fix.server_addr_port)
    client_socket0.connect(fix.server_addr_port)
    check_socket_echo(client_socket0)
    check_socket_echo(client_socket1)


@skipif_missing_tcp_authopt
@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_vrf_overlap_ao_samekey(exit_stack: ExitStack, address_family):
    """Single server serving both VRF and non-VRF client with same password.

    This requires no special support from TCP-AO.
    """
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)
    set_tcp_authopt_key(fix.listen_socket, tcp_authopt_key(key="11111"))

    client_socket1 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    client_socket2 = fix.create_client_socket(fix.nsfixture.client2_netns_name)

    set_tcp_authopt_key(client_socket1, tcp_authopt_key(key="11111"))
    set_tcp_authopt_key(client_socket2, tcp_authopt_key(key="11111"))
    client_socket1.connect(fix.server_addr_port)
    client_socket2.connect(fix.server_addr_port)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)


@skipif_missing_tcp_authopt
@pytest.mark.skip("no ifindex in tcp_authopt_key yet")
@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_vrf_overlap_ao(exit_stack: ExitStack, address_family):
    """Single server serving both VRF and non-VRF client with different passwords

    This requ
    """
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)
    set_tcp_authopt_key(fix.listen_socket, tcp_authopt_key(key=b"11111", ifindex=4))
    set_tcp_authopt_key(fix.listen_socket, tcp_authopt_key(key=b"22222", ifindex=0))

    client_socket1 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    client_socket2 = fix.create_client_socket(fix.nsfixture.client2_netns_name)

    set_tcp_authopt_key(client_socket1, tcp_authopt_key(key=b"11111"))
    set_tcp_authopt_key(client_socket2, tcp_authopt_key(key=b"22222"))
    client_socket1.connect(fix.server_addr_port)
    client_socket2.connect(fix.server_addr_port)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)
