# SPDX-License-Identifier: GPL-2.0
import logging
import socket
import subprocess
from contextlib import ExitStack
from socket import AddressFamily
from typing import Optional

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
    :ivar enable_sniffer: Enable the sniffer (default)
    """

    address_family: AddressFamily
    _server_address_family: Optional[AddressFamily]
    _client_address_family: Optional[AddressFamily]

    bind_client_addr: bool = True
    """If True then bind client socket to client_addr"""

    bind_server_addr: bool = True
    """If False then listen on wildcard otherwise only on the specific server address"""

    sniffer_session: FullTCPSniffSession

    client_bind_port: int = 0
    """Port to bind the client socket to"""

    _client_real_port: int = 0
    """Real port that the client socket is bound to"""

    @property
    def client_port(self) -> int:
        """Real port that the client socket is bound to"""
        return self._client_real_port

    @property
    def server_address_family(self) -> AddressFamily:
        return self._server_address_family or self.address_family

    @property
    def client_address_family(self) -> AddressFamily:
        return self._client_address_family or self.address_family

    def __init__(
        self,
        *,
        address_family: AddressFamily = socket.AF_INET,
        server_address_family: Optional[AddressFamily] = None,
        client_address_family: Optional[AddressFamily] = None,
        tcp_authopt_key: tcp_authopt_key = None,
        server_thread_kwargs=None,
        tcp_md5_key=None,
        enable_sniffer=True,
        sniffer_kwargs=None,
        capture_on_client=False,
    ):
        self.address_family = address_family
        self._server_address_family = server_address_family
        self._client_address_family = client_address_family
        self.server_port = DEFAULT_TCP_SERVER_PORT
        self.client_bind_port = 27972
        self.server_thread = SimpleServerThread(
            mode="echo", **(server_thread_kwargs or {})
        )

        self.tcp_authopt_key = tcp_authopt_key
        self.tcp_md5_key = tcp_md5_key

        self.enable_sniffer = enable_sniffer
        self.sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
        self.sniffer_kwargs = sniffer_kwargs or {}
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
        bind_addr = self.client_addr if self.bind_client_addr else ""
        return create_client_socket(
            ns=self.nsfixture.client_netns_name,
            family=self.client_address_family,
            bind_addr=bind_addr,
            bind_port=bind_port,
        )

    def _setup_capture(self):
        if not self.enable_sniffer:
            return

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
        self.server_addr = self.nsfixture.get_server_addr(self.server_address_family)
        self.client_addr = self.nsfixture.get_client_addr(self.client_address_family)

        listen_addr = self.server_addr if self.bind_server_addr else ""
        self.listen_socket = create_listen_socket(
            ns=self.nsfixture.server_netns_name,
            family=self.server_address_family,
            bind_addr=listen_addr,
            bind_port=self.server_port,
        )
        self.exit_stack.enter_context(self.listen_socket)
        self.client_socket = self.create_client_socket(bind_port=self.client_bind_port)
        self._client_real_port = self.client_socket.getsockname()[1]
        if self.client_bind_port:
            assert self.client_port == self.client_bind_port
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
        return self

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

    def _get_state_via_ss(self, netns: str, filter: str) -> Optional[str]:
        # Every namespace should have at most one socket
        # the "state connected" filter includes TIME-WAIT but not LISTEN
        cmd = f"ss --net {netns} --numeric --no-header --tcp state connected {filter}"
        out = subprocess.check_output(cmd, text=True, shell=True)
        lines = out.splitlines()
        # No socket found usually means "CLOSED". It is distinct from "TIME-WAIT"
        if len(lines) == 0:
            return None
        if len(lines) > 1:
            raise ValueError("At most one line expected")
        return lines[0].split()[0]

    def get_client_tcp_state(self) -> Optional[str]:
        return self._get_state_via_ss(
            self.client_netns_name,
            f"sport {self.client_port} dport {self.server_port}",
        )

    def get_server_tcp_state(self) -> Optional[str]:
        return self._get_state_via_ss(
            self.server_netns_name,
            f"sport {self.server_port} dport {self.client_port}",
        )


def log_tcp_authopt_packet(p):
    logger.info("sniff %s", format_tcp_authopt_packet(p, include_seq=True))
