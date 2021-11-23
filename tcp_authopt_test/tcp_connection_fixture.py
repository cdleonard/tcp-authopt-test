# SPDX-License-Identifier: GPL-2.0
import logging
import socket
import subprocess
from contextlib import ExitStack

import pytest
from scapy.data import ETH_P_IP, ETH_P_IPV6
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

from . import linux_tcp_authopt
from .full_tcp_sniff_session import FullTCPSniffSession
from .linux_tcp_authopt import set_tcp_authopt_key, tcp_authopt_key
from .netns_fixture import NamespaceFixture
from .scapy_utils import (
    AsyncSnifferContext,
    create_capture_socket,
    create_l2socket,
    format_tcp_authopt_packet,
)
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    create_client_socket,
    create_listen_socket,
    netns_context,
    nstat_json,
)

logger = logging.getLogger(__name__)


class TCPConnectionFixture:
    """Test fixture with an instrumented TCP connection

    Includes:
    * pair of network namespaces
    * one listen socket
    * server thread with echo protocol
    * one client socket
    * one async sniffer on the server interface
    * A `FullTCPSniffSession` examining TCP packets
    * l2socket allowing packet injection from client

    :ivar tcp_md5_key: Secret key for md5 (addr is implicit)
    """

    sniffer_session: FullTCPSniffSession

    def __init__(
        self,
        address_family=socket.AF_INET,
        sniffer_kwargs=None,
        tcp_authopt_key: tcp_authopt_key = None,
        server_thread_kwargs=None,
        tcp_md5_key=None,
        capture_on_client=False,
    ):
        self.address_family = address_family
        self.server_port = DEFAULT_TCP_SERVER_PORT
        self.client_port = 27972
        self.sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
        if sniffer_kwargs is None:
            sniffer_kwargs = {}
        self.sniffer_kwargs = sniffer_kwargs
        self.tcp_authopt_key = tcp_authopt_key
        self.server_thread = SimpleServerThread(
            mode="echo", **(server_thread_kwargs or {})
        )
        self.tcp_md5_key = tcp_md5_key
        self.capture_on_client = capture_on_client

    def _set_tcp_md5(self):
        from . import linux_tcp_md5sig
        from .sockaddr import sockaddr_convert

        linux_tcp_md5sig.setsockopt_md5sig(
            self.listen_socket,
            linux_tcp_md5sig.tcp_md5sig(
                key=self.tcp_md5_key, addr=sockaddr_convert(self.client_addr)
            ),
        )
        linux_tcp_md5sig.setsockopt_md5sig(
            self.client_socket,
            linux_tcp_md5sig.tcp_md5sig(
                key=self.tcp_md5_key, addr=sockaddr_convert(self.server_addr)
            ),
        )

    def create_client_socket(self, bind_port=0):
        return create_client_socket(
            ns=self.nsfixture.client_netns_name,
            family=self.address_family,
            bind_addr=self.client_addr,
            bind_port=bind_port,
        )

    def _setup_capture(self):
        capture_filter = f"tcp port {self.server_port}"
        if self.capture_on_client:
            capture_netns = self.nsfixture.server_netns_name
        else:
            capture_netns = self.nsfixture.client_netns_name
        self.capture_socket = create_capture_socket(
            ns=capture_netns,
            iface="veth0",
            filter=capture_filter,
        )
        self.exit_stack.enter_context(self.capture_socket)

        self.sniffer = AsyncSnifferContext(
            opened_socket=self.capture_socket,
            session=self.sniffer_session,
            prn=log_tcp_authopt_packet,
            **self.sniffer_kwargs,
        )
        self.exit_stack.enter_context(self.sniffer)

    def __enter__(self):
        if self.tcp_authopt_key and not linux_tcp_authopt.has_tcp_authopt():
            pytest.skip("Need TCP_AUTHOPT")

        self.exit_stack = ExitStack()
        self.exit_stack.__enter__()

        self.nsfixture = self.exit_stack.enter_context(NamespaceFixture())
        self.server_addr = self.nsfixture.get_server_addr(self.address_family)
        self.client_addr = self.nsfixture.get_client_addr(self.address_family)

        self.listen_socket = create_listen_socket(
            ns=self.nsfixture.server_netns_name,
            family=self.address_family,
            bind_addr=self.server_addr,
            bind_port=self.server_port,
        )
        self.exit_stack.enter_context(self.listen_socket)
        self.client_socket = self.create_client_socket(bind_port=self.client_port)
        self.exit_stack.enter_context(self.client_socket)
        self.server_thread.add_listen_socket(self.listen_socket)
        self.exit_stack.enter_context(self.server_thread)

        if self.tcp_authopt_key:
            set_tcp_authopt_key(self.listen_socket, self.tcp_authopt_key)
            set_tcp_authopt_key(self.client_socket, self.tcp_authopt_key)

        if self.tcp_md5_key:
            self._set_tcp_md5()

        self._setup_capture()

        self.client_l2socket = create_l2socket(
            ns=self.nsfixture.client_netns_name, iface="veth0"
        )
        self.exit_stack.enter_context(self.client_l2socket)
        self.server_l2socket = create_l2socket(
            ns=self.nsfixture.server_netns_name, iface="veth0"
        )
        self.exit_stack.enter_context(self.server_l2socket)

    def __exit__(self, *args):
        self.exit_stack.__exit__(*args)

    @property
    def ethertype(self):
        if self.address_family == socket.AF_INET:
            return ETH_P_IP
        elif self.address_family == socket.AF_INET6:
            return ETH_P_IPV6
        else:
            raise ValueError("bad address_family={self.address_family}")

    def scapy_iplayer(self):
        if self.address_family == socket.AF_INET:
            return IP
        elif self.address_family == socket.AF_INET6:
            return IPv6
        else:
            raise ValueError("bad address_family={self.address_family}")

    def create_client2server_packet(self) -> Packet:
        return (
            Ether(
                type=self.ethertype,
                src=self.nsfixture.client_mac_addr,
                dst=self.nsfixture.server_mac_addr,
            )
            / self.scapy_iplayer()(src=str(self.client_addr), dst=str(self.server_addr))
            / TCP(sport=self.client_port, dport=self.server_port)
        )

    def create_server2client_packet(self) -> Packet:
        return (
            Ether(
                type=self.ethertype,
                src=self.nsfixture.server_mac_addr,
                dst=self.nsfixture.client_mac_addr,
            )
            / self.scapy_iplayer()(src=str(self.server_addr), dst=str(self.client_addr))
            / TCP(sport=self.server_port, dport=self.client_port)
        )

    @property
    def server_addr_port(self):
        return (str(self.server_addr), self.server_port)

    @property
    def server_netns_name(self):
        return self.nsfixture.server_netns_name

    @property
    def client_netns_name(self):
        return self.nsfixture.client_netns_name

    def client_nstat_json(self):
        with netns_context(self.client_netns_name):
            return nstat_json()

    def server_nstat_json(self):
        with netns_context(self.server_netns_name):
            return nstat_json()

    def assert_no_snmp_output_failures(self):
        client_nstat_dict = self.client_nstat_json()
        assert client_nstat_dict["TcpExtTCPAuthOptFailure"] == 0
        server_nstat_dict = self.server_nstat_json()
        assert server_nstat_dict["TcpExtTCPAuthOptFailure"] == 0

    def _get_state_via_ss(self, command_prefix: str):
        # Every namespace should have at most one socket
        # the "state connected" filter includes TIME-WAIT but not LISTEN
        cmd = command_prefix + "ss --numeric --no-header --tcp state connected"
        out = subprocess.check_output(cmd, text=True, shell=True)
        lines = out.splitlines()
        # No socket found usually means "CLOSED". It is distinct from "TIME-WAIT"
        if len(lines) == 0:
            return None
        if len(lines) > 1:
            raise ValueError("At most one line expected")
        return lines[0].split()[0]

    def get_client_tcp_state(self):
        return self._get_state_via_ss(f"ip netns exec {self.client_netns_name} ")

    def get_server_tcp_state(self):
        return self._get_state_via_ss(f"ip netns exec {self.server_netns_name} ")


def log_tcp_authopt_packet(p):
    logger.info("sniff %s", format_tcp_authopt_packet(p, include_seq=True))
