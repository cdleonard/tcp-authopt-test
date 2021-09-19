# SPDX-License-Identifier: GPL-2.0
"""Capture packets with TCP-AO and verify signatures"""

import logging
import os
import socket
from contextlib import ExitStack, nullcontext

import pytest
import waiting
from scapy.layers.inet import TCP

from . import linux_tcp_authopt
from .conftest import skipif_missing_tcp_authopt
from .full_tcp_sniff_session import FullTCPSniffSession
from .linux_tcp_authopt import set_tcp_authopt_key, tcp_authopt_key
from .netns_fixture import NamespaceFixture
from .scapy_tcp_authopt import TcpAuthOptAlg_HMAC_SHA1, add_tcp_authopt_signature
from .scapy_utils import AsyncSnifferContext, scapy_sniffer_stop, tcp_seq_wrap
from .server import SimpleServerThread
from .tcp_connection_fixture import TCPConnectionFixture
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_client_socket,
    create_listen_socket,
    nstat_json,
    socket_set_linger,
)
from .validator import TcpAuthValidator, TcpAuthValidatorKey

logger = logging.getLogger(__name__)
pytestmark = skipif_missing_tcp_authopt
DEFAULT_TCP_AUTHOPT_KEY = tcp_authopt_key(
    alg=linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
    key=b"hello",
)


def can_capture():
    # This is too restrictive:
    return os.geteuid() == 0


skipif_cant_capture = pytest.mark.skipif(
    not can_capture(), reason="run as root to capture packets"
)


def get_alg_id(alg_name) -> int:
    if alg_name == "HMAC-SHA-1-96":
        return linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96
    elif alg_name == "AES-128-CMAC-96":
        return linux_tcp_authopt.TCP_AUTHOPT_ALG.AES_128_CMAC_96
    else:
        raise ValueError()


@skipif_cant_capture
@pytest.mark.parametrize(
    "address_family,alg_name,include_options,transfer_data",
    [
        (socket.AF_INET, "HMAC-SHA-1-96", True, True),
        (socket.AF_INET, "AES-128-CMAC-96", True, True),
        (socket.AF_INET, "AES-128-CMAC-96", False, True),
        (socket.AF_INET6, "HMAC-SHA-1-96", True, True),
        (socket.AF_INET6, "HMAC-SHA-1-96", False, True),
        (socket.AF_INET6, "AES-128-CMAC-96", True, True),
        (socket.AF_INET, "HMAC-SHA-1-96", True, False),
        (socket.AF_INET6, "AES-128-CMAC-96", False, False),
    ],
)
def test_verify_capture(
    exit_stack, address_family, alg_name, include_options, transfer_data
):
    master_key = b"testvector"
    alg_id = get_alg_id(alg_name)

    session = FullTCPSniffSession(server_port=DEFAULT_TCP_SERVER_PORT)
    sniffer = exit_stack.enter_context(
        AsyncSnifferContext(
            filter=f"inbound and tcp port {DEFAULT_TCP_SERVER_PORT}",
            iface="lo",
            session=session,
        )
    )

    listen_socket = create_listen_socket(family=address_family)
    listen_socket = exit_stack.enter_context(listen_socket)
    exit_stack.enter_context(SimpleServerThread(listen_socket, mode="echo"))

    client_socket = socket.socket(address_family, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)

    key = tcp_authopt_key(alg=alg_id, key=master_key, include_options=include_options)
    set_tcp_authopt_key(listen_socket, key)
    set_tcp_authopt_key(client_socket, key)

    # even if one signature is incorrect keep processing the capture
    old_nstat = nstat_json()
    valkey = TcpAuthValidatorKey(
        key=master_key, alg_name=alg_name, include_options=include_options
    )
    validator = TcpAuthValidator(keys=[valkey])

    try:
        client_socket.settimeout(1.0)
        client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
        if transfer_data:
            for _ in range(5):
                check_socket_echo(client_socket)
        client_socket.close()
        session.wait_close()
    except socket.timeout:
        # If invalid packets are sent let the validator run
        logger.warning("socket timeout", exc_info=True)
        pass

    sniffer.stop()

    logger.info("capture: %r", sniffer.results)
    for p in sniffer.results:
        validator.handle_packet(p)
    validator.raise_errors()

    new_nstat = nstat_json()
    assert old_nstat["TcpExtTCPAuthOptFailure"] == new_nstat["TcpExtTCPAuthOptFailure"]


@pytest.mark.parametrize("mode", ["none", "ao", "ao-addrbind", "md5"])
def test_v4mapv6(exit_stack, mode: str):
    """Test ipv4 client and ipv6 server with and without TCP-AO

    By default any IPv6 server will also receive packets from IPv4 clients. This
    is not currently supported by TCP_AUTHOPT but it should fail in an orderly
    manner.
    """
    nsfixture = NamespaceFixture()
    exit_stack.enter_context(nsfixture)
    server_ipv4_addr = nsfixture.get_addr(socket.AF_INET, 1)

    listen_socket = create_listen_socket(
        ns=nsfixture.server_netns_name, family=socket.AF_INET6
    )
    listen_socket = exit_stack.enter_context(listen_socket)

    server_thread = SimpleServerThread(listen_socket, mode="echo")
    exit_stack.enter_context(server_thread)

    client_socket = create_client_socket(
        ns=nsfixture.client_netns_name,
        family=socket.AF_INET,
    )
    client_socket = exit_stack.push(client_socket)

    if mode == "ao":
        alg = linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96
        key = linux_tcp_authopt.tcp_authopt_key(alg=alg, key="hello")
        linux_tcp_authopt.set_tcp_authopt_key(listen_socket, key)
        linux_tcp_authopt.set_tcp_authopt_key(client_socket, key)

    if mode == "ao-addrbind":
        alg = linux_tcp_authopt.TCP_AUTHOPT_ALG.HMAC_SHA_1_96
        client_ipv6_addr = nsfixture.get_addr(socket.AF_INET6, 2)
        server_key = linux_tcp_authopt.tcp_authopt_key(
            alg=alg, key="hello", addr=client_ipv6_addr
        )
        server_key.flags = linux_tcp_authopt.TCP_AUTHOPT_KEY_FLAG.BIND_ADDR
        linux_tcp_authopt.set_tcp_authopt_key(listen_socket, server_key)

        client_key = linux_tcp_authopt.tcp_authopt_key(alg=alg, key="hello")
        linux_tcp_authopt.set_tcp_authopt_key(client_socket, client_key)

    if mode == "md5":
        from . import linux_tcp_md5sig

        server_key = linux_tcp_md5sig.tcp_md5sig(key=b"hello")
        server_key.set_ipv6_addr_all()
        linux_tcp_md5sig.setsockopt_md5sig(listen_socket, server_key)
        client_key = linux_tcp_md5sig.tcp_md5sig(key=b"hellx")
        client_key.set_ipv4_addr_all()
        linux_tcp_md5sig.setsockopt_md5sig(client_socket, client_key)

    with pytest.raises(socket.timeout) if mode != "none" else nullcontext():
        client_socket.connect((str(server_ipv4_addr), DEFAULT_TCP_SERVER_PORT))
        check_socket_echo(client_socket)
    client_socket.close()


@pytest.mark.parametrize(
    "address_family,signed",
    [(socket.AF_INET, True), (socket.AF_INET, False)],
)
def test_rst(exit_stack: ExitStack, address_family, signed: bool):
    """Check that an unsigned RST breaks a normal connection but not one protected by TCP-AO"""

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(sniffer_session=sniffer_session)
    if signed:
        context.tcp_authopt_key = DEFAULT_TCP_AUTHOPT_KEY
    exit_stack.enter_context(context)

    # connect
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)

    client_isn, server_isn = sniffer_session.get_client_server_isn()
    p = context.create_client2server_packet()
    p[TCP].flags = "R"
    p[TCP].seq = tcp_seq_wrap(client_isn + 1001)
    p[TCP].ack = tcp_seq_wrap(server_isn + 1001)
    context.client_l2socket.send(p)

    if signed:
        # When protected by TCP-AO unsigned RSTs are ignored.
        check_socket_echo(context.client_socket)
    else:
        # By default an RST that guesses seq can kill the connection.
        with pytest.raises(ConnectionResetError):
            check_socket_echo(context.client_socket)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_rst_signed_manually(exit_stack: ExitStack, address_family):
    """Check that an manually signed RST breaks a connection protected by TCP-AO"""

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(
        address_family=address_family, sniffer_session=sniffer_session
    )
    context.tcp_authopt_key = key = DEFAULT_TCP_AUTHOPT_KEY
    exit_stack.enter_context(context)

    # connect
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)

    client_isn, server_isn = sniffer_session.get_client_server_isn()
    p = context.create_client2server_packet()
    p[TCP].flags = "R"
    p[TCP].seq = tcp_seq_wrap(client_isn + 1001)
    p[TCP].ack = tcp_seq_wrap(server_isn + 1001)

    add_tcp_authopt_signature(
        p, TcpAuthOptAlg_HMAC_SHA1(), key.key, client_isn, server_isn
    )
    context.client_l2socket.send(p)

    # The server socket will close in response to RST without a TIME-WAIT
    # Attempting to send additional packets will result in a timeout because
    # the signature can't be validated.
    with pytest.raises(socket.timeout):
        check_socket_echo(context.client_socket)


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_tw_ack(exit_stack: ExitStack, address_family):
    """Manually sent a duplicate ACK after FIN and check TWSK signs replies correctly

    Kernel has a custom code path for this
    """

    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(
        address_family=address_family, sniffer_session=sniffer_session
    )
    context.tcp_authopt_key = key = DEFAULT_TCP_AUTHOPT_KEY
    exit_stack.enter_context(context)

    # connect and close nicely
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)
    assert context.get_client_tcp_state() == "ESTAB"
    assert context.get_server_tcp_state() == "ESTAB"
    context.client_socket.close()
    sniffer_session.wait_close()

    assert context.get_client_tcp_state() == "TIME-WAIT"
    assert context.get_server_tcp_state() is None

    # Sent a duplicate FIN/ACK
    client_isn, server_isn = sniffer_session.get_client_server_isn()
    p = context.create_server2client_packet()
    p[TCP].flags = "FA"
    p[TCP].seq = tcp_seq_wrap(server_isn + 1001)
    p[TCP].ack = tcp_seq_wrap(client_isn + 1002)
    add_tcp_authopt_signature(
        p, TcpAuthOptAlg_HMAC_SHA1(), key.key, server_isn, client_isn
    )
    pr = context.server_l2socket.sr1(p)
    assert pr[TCP].ack == tcp_seq_wrap(server_isn + 1001)
    assert pr[TCP].seq == tcp_seq_wrap(client_isn + 1001)
    assert pr[TCP].flags == "A"

    scapy_sniffer_stop(context.sniffer)

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()

    # The server does not have enough state to validate the ACK from TIME-WAIT
    # so it reports a failure.
    assert context.server_nstat_json()["TcpExtTCPAuthOptFailure"] == 1
    assert context.client_nstat_json()["TcpExtTCPAuthOptFailure"] == 0


@pytest.mark.parametrize("address_family", [socket.AF_INET, socket.AF_INET6])
def test_tw_rst(exit_stack: ExitStack, address_family):
    """Manually sent a signed invalid packet after FIN and check TWSK signs RST correctly

    Kernel has a custom code path for this
    """
    key = DEFAULT_TCP_AUTHOPT_KEY
    sniffer_session = FullTCPSniffSession(DEFAULT_TCP_SERVER_PORT)
    context = TCPConnectionFixture(
        address_family=address_family,
        sniffer_session=sniffer_session,
        tcp_authopt_key=key,
    )
    context.server_thread.keep_half_open = True
    exit_stack.enter_context(context)

    # connect, transfer data and close client nicely
    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)
    context.client_socket.close()

    # since server keeps connection open client goes to FIN-WAIT-2
    def check_socket_states():
        client_tcp_state_name = context.get_client_tcp_state()
        server_tcp_state_name = context.get_server_tcp_state()
        logger.info("%s %s", client_tcp_state_name, server_tcp_state_name)
        return (
            client_tcp_state_name == "FIN-WAIT-2"
            and server_tcp_state_name == "CLOSE-WAIT"
        )

    waiting.wait(check_socket_states)

    # sending a FIN-ACK with incorrect seq makes
    # tcp_timewait_state_process return a TCP_TW_RST
    client_isn, server_isn = sniffer_session.get_client_server_isn()
    p = context.create_server2client_packet()
    p[TCP].flags = "FA"
    p[TCP].seq = tcp_seq_wrap(server_isn + 1001 + 1)
    p[TCP].ack = tcp_seq_wrap(client_isn + 1002)
    add_tcp_authopt_signature(
        p, TcpAuthOptAlg_HMAC_SHA1(), key.key, server_isn, client_isn
    )
    context.server_l2socket.send(p)

    # remove delay by scapy trick?
    import time

    time.sleep(1)
    scapy_sniffer_stop(context.sniffer)

    # Check client socket moved from FIN-WAIT-2 to CLOSED
    assert context.get_client_tcp_state() is None

    # Check some RST was seen
    def is_tcp_rst(p):
        return TCP in p and p[TCP].flags.R

    assert any(is_tcp_rst(p) for p in context.sniffer.results)

    # Check everything was valid
    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()

    # Check no snmp failures
    context.assert_no_snmp_output_failures()


def test_rst_linger(exit_stack: ExitStack):
    """Test RST sent deliberately via SO_LINGER is valid"""
    context = TCPConnectionFixture(
        sniffer_kwargs=dict(count=8), tcp_authopt_key=DEFAULT_TCP_AUTHOPT_KEY
    )
    exit_stack.enter_context(context)

    context.client_socket.connect((str(context.server_addr), context.server_port))
    check_socket_echo(context.client_socket)
    socket_set_linger(context.client_socket, 1, 0)
    context.client_socket.close()

    context.sniffer.join(timeout=3)

    val = TcpAuthValidator()
    val.keys.append(TcpAuthValidatorKey(key=b"hello", alg_name="HMAC-SHA-1-96"))
    for p in context.sniffer.results:
        val.handle_packet(p)
    val.raise_errors()

    def is_tcp_rst(p):
        return TCP in p and p[TCP].flags.R

    assert any(is_tcp_rst(p) for p in context.sniffer.results)
