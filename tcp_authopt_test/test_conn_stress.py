import logging
import socket
import subprocess
import typing
from contextlib import ExitStack

import pytest

from .linux_tcp_authopt import set_tcp_authopt_key_kwargs
from .linux_tcp_md5sig import setsockopt_md5sig_kwargs
from .netns_fixture import NamespaceFixture
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    create_client_socket,
    create_listen_socket,
    nstat_json,
    socket_set_linger,
)

logger = logging.getLogger(__name__)


@pytest.mark.parametrize(
    "sign_mode",
    [
        pytest.param("ao", marks=pytest.mark.xfail),
        "md5",
        "none",
    ],
)
def test_many_conns(exit_stack: ExitStack, sign_mode: str):
    """Stress connection establishment

    Creating so many connections that tcp_max_tw_buckets overflows results in a weird
    port reuse scenario which fails with AO
    """
    secret_key = b"12345"
    linger_onoff = 1
    linger_value = 10
    listen_depth = 1024
    address_family = socket.AF_INET
    client_timeout = 10
    run_tcpdump = True

    # Reproduce issue with few ports:
    if True:
        iter_count = 200
        max_tw_buckets = 20
        local_port_count = 100
    else:
        iter_count = 70000
        local_port_count = 0
        max_tw_buckets = 0

    nsfixture = exit_stack.enter_context(NamespaceFixture())
    if run_tcpdump:
        from .tcpdump import tcpdump_capture_nsfixture

        exit_stack.enter_context(tcpdump_capture_nsfixture(NamespaceFixture()))

    script = f"""
set -e -x
if {"true" if max_tw_buckets else "false"}; then
    ip netns exec {nsfixture.client_netns_name} sysctl net.ipv4.tcp_max_tw_buckets={max_tw_buckets}
    ip netns exec {nsfixture.server_netns_name} sysctl net.ipv4.tcp_max_tw_buckets={max_tw_buckets}
else
    ip netns exec {nsfixture.client_netns_name} sysctl net.ipv4.tcp_max_tw_buckets
    ip netns exec {nsfixture.server_netns_name} sysctl net.ipv4.tcp_max_tw_buckets
fi
if {"true" if local_port_count else "false"}; then
    ip netns exec {nsfixture.client_netns_name} sysctl net.ipv4.ip_local_port_range='10000 {10000 + local_port_count}'
else
    sysctl net.ipv4.ip_local_port_range
fi
ip netns exec {nsfixture.client_netns_name} cat /proc/net/sockstat
ip netns exec {nsfixture.server_netns_name} cat /proc/net/sockstat
"""
    subprocess.run(script, shell=True, check=True)

    server_addr = nsfixture.get_addr(address_family, 1)
    client_addr = nsfixture.get_addr(address_family, 2)
    server_addr_port = (str(server_addr), DEFAULT_TCP_SERVER_PORT)
    listen_socket = create_listen_socket(
        family=address_family,
        ns=nsfixture.server_netns_name,
        bind_addr=server_addr,
        listen_depth=listen_depth,
    )
    exit_stack.enter_context(listen_socket)

    if sign_mode == "ao":
        set_tcp_authopt_key_kwargs(listen_socket, key=secret_key)
    elif sign_mode == "md5":
        setsockopt_md5sig_kwargs(listen_socket, key=secret_key, addr=client_addr)
    elif sign_mode != "none":
        raise ValueError(f"Bad sign_mode={sign_mode}")

    server_thread = SimpleServerThread(listen_socket)
    exit_stack.enter_context(server_thread)

    def assert_no_snmp_failures():
        from .conftest import has_tcp_authopt_snmp

        if not has_tcp_authopt_snmp():
            return None
        client_nstat = nstat_json(namespace=nsfixture.client_netns_name)
        server_nstat = nstat_json(namespace=nsfixture.server_netns_name)
        assert (
            client_nstat["TcpExtTCPAuthOptFailure"] == 0
            and server_nstat["TcpExtTCPAuthOptFailure"] == 0
        )

    client_port_use_count: typing.Dict[int, int] = {}

    fail_connect = False
    for iternum in range(iter_count):
        with create_client_socket(
            family=address_family,
            ns=nsfixture.client_netns_name,
            timeout=client_timeout,
            bind_addr=client_addr,
        ) as client_socket:
            if sign_mode == "ao":
                set_tcp_authopt_key_kwargs(client_socket, key=secret_key)
            elif sign_mode == "md5":
                setsockopt_md5sig_kwargs(
                    client_socket,
                    key=secret_key,
                    addr=server_addr,
                )
            elif sign_mode != "none":
                raise ValueError(f"Bad sign_mode={sign_mode}")

            client_port = client_socket.getsockname()[1]
            reuse_count = client_port_use_count.get(client_port, 0)
            client_port_use_count[client_port] = reuse_count + 1
            if reuse_count > 1:
                logger.info("client port %d used %d times", client_port, reuse_count)

            try:
                client_socket.connect(server_addr_port)
            except:
                logger.info("client_socket=%r", client_socket)
                logger.error("failed connect on iteration %d", iternum, exc_info=True)
                fail_connect = True
                break

            socket_set_linger(client_socket, linger_onoff, linger_value)
            if iternum % (iter_count / 100) == 0:
                logger.info("pass %d iter", iternum)
            client_socket.close()

    script = f"""
set -e -x
ip netns exec {nsfixture.client_netns_name} cat /proc/net/sockstat
ip netns exec {nsfixture.server_netns_name} cat /proc/net/sockstat
ip netns exec {nsfixture.client_netns_name} nstat -a
ip netns exec {nsfixture.server_netns_name} nstat -a
"""
    subprocess.run(script, shell=True, check=True)

    assert_no_snmp_failures()
    assert not fail_connect
