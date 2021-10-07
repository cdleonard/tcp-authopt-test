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
from .linux_tcp_authopt import (
    TCP_AUTHOPT_KEY_FLAG,
    set_tcp_authopt_key,
    tcp_authopt_key,
)
from . import linux_tcp_authopt
from . import linux_tcp_md5sig
import errno


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

    @property
    def vrf1_ifindex(self):
        return self.nsfixture.server_vrf1_ifindex

    @property
    def vrf2_ifindex(self):
        return self.nsfixture.server_vrf2_ifindex

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
        return self

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


def set_server_md5(fix, key=b"000", **kw):
    linux_tcp_md5sig.setsockopt_md5sig_kwargs(
        fix.listen_socket, key=key, addr=fix.client_addr, **kw
    )


def set_server_md5_key0(fix, key=b"000"):
    return set_server_md5(fix, key=key)


def set_server_md5_key1(fix, key=b"111"):
    return set_server_md5(fix, key=key, ifindex=fix.vrf1_ifindex)


def set_server_md5_key2(fix, key=b"222"):
    return set_server_md5(fix, key=key, ifindex=fix.vrf2_ifindex)


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


@pytest.mark.parametrize("address_family", [socket.AF_INET])
def test_vrf_overlap_md5_prefix(exit_stack: ExitStack, address_family):
    """VRF keys should take precedence even if prefixlen is low"""
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)
    set_server_md5(fix, key=b"fail", prefixlen=16)
    set_server_md5(
        fix, key=b"pass", ifindex=fix.nsfixture.server_vrf1_ifindex, prefixlen=1
    )
    set_server_md5(fix, key=b"fail", prefixlen=24)

    # connect via VRF
    client_socket = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    set_client_md5_key(fix, client_socket, b"pass")
    client_socket.connect(fix.server_addr_port)


def assert_raises_enoent(func):
    with pytest.raises(OSError) as e:
        func()
    assert e.value.errno == errno.ENOENT


def test_vrf_overlap_md5_del_0110():
    """Removing keys should not raise ENOENT because they are distinct"""
    with VrfFixture() as fix:
        set_server_md5(fix, key=b"000")
        set_server_md5(fix, key=b"111", ifindex=fix.vrf1_ifindex)
        set_server_md5(fix, key=b"", ifindex=fix.vrf1_ifindex)
        set_server_md5(fix, key=b"")
        assert_raises_enoent(lambda: set_server_md5(fix, key=b""))


def test_vrf_overlap_md5_del_1001():
    """Removing keys should not raise ENOENT because they are distinct"""
    with VrfFixture() as fix:
        set_server_md5(fix, key=b"111", ifindex=fix.vrf1_ifindex)
        set_server_md5(fix, key=b"000")
        set_server_md5(fix, key=b"")
        set_server_md5(fix, key=b"", ifindex=fix.vrf1_ifindex)
        assert_raises_enoent(lambda: set_server_md5(fix, key=b""))


def test_vrf_overlap_md5_del_1010():
    """Removing keys should not raise ENOENT because they are distinct"""
    with VrfFixture() as fix:
        set_server_md5(fix, key=b"111", ifindex=fix.vrf1_ifindex)
        set_server_md5(fix, key=b"000")
        set_server_md5(fix, key=b"", ifindex=fix.vrf1_ifindex)
        set_server_md5(fix, key=b"")
        assert_raises_enoent(lambda: set_server_md5(fix, key=b""))


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
@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_vrf_overlap_ao(exit_stack: ExitStack, address_family):
    """Single server serving both VRF and non-VRF client with different passwords

    This requires kernel to handle ifindex
    """
    fix = VrfFixture(address_family)
    exit_stack.enter_context(fix)
    set_tcp_authopt_key(
        fix.listen_socket,
        tcp_authopt_key(
            key=b"00000",
            ifindex=0,
            flags=TCP_AUTHOPT_KEY_FLAG.IFINDEX,
        ),
    )
    set_tcp_authopt_key(
        fix.listen_socket,
        tcp_authopt_key(
            key=b"11111", ifindex=fix.vrf1_ifindex, flags=TCP_AUTHOPT_KEY_FLAG.IFINDEX
        ),
    )
    set_tcp_authopt_key(
        fix.listen_socket,
        tcp_authopt_key(
            key=b"22222", ifindex=fix.vrf2_ifindex, flags=TCP_AUTHOPT_KEY_FLAG.IFINDEX
        ),
    )

    client_socket0 = fix.create_client_socket(fix.nsfixture.client0_netns_name)
    client_socket1 = fix.create_client_socket(fix.nsfixture.client1_netns_name)
    client_socket2 = fix.create_client_socket(fix.nsfixture.client2_netns_name)
    set_tcp_authopt_key(client_socket0, tcp_authopt_key(key=b"00000"))
    set_tcp_authopt_key(client_socket1, tcp_authopt_key(key=b"11111"))
    set_tcp_authopt_key(client_socket2, tcp_authopt_key(key=b"22222"))
    client_socket0.connect(fix.server_addr_port)
    client_socket1.connect(fix.server_addr_port)
    client_socket2.connect(fix.server_addr_port)
    check_socket_echo(client_socket0)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)
    check_socket_echo(client_socket0)
    check_socket_echo(client_socket1)
    check_socket_echo(client_socket2)
