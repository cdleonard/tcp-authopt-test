# SPDX-License-Identifier: GPL-2.0
"""Validate SNE implementation for TCP-AO"""

import logging
import socket
import subprocess
from contextlib import ExitStack
from ipaddress import ip_address
from threading import Thread

import pytest
import waiting
from scapy.layers.inet import TCP
from scapy.packet import Packet, Raw

from .exthread import ExThread
from .linux_tcp_authopt import (
    TCP_AUTHOPT_ALG,
    set_tcp_authopt_key_kwargs,
    tcp_authopt_key,
)
from .linux_tcp_repair import get_tcp_repair_recv_send_queue_seq, tcp_repair_toggle
from .linux_tcp_repair_authopt import get_tcp_repair_authopt
from .netns_fixture import NamespaceFixture
from .scapy_conntrack import TCPConnectionKey, TCPConnectionTracker
from .scapy_tcp_authopt import (
    TcpAuthOptAlg_HMAC_SHA1,
    add_tcp_authopt_signature,
    check_tcp_authopt_signature,
)
from .scapy_utils import AsyncSnifferContext, create_capture_socket, tcp_seq_wrap
from .server import SimpleServerThread
from .tcp_connection_fixture import TCPConnectionFixture
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_client_socket,
    create_listen_socket,
    netns_context,
    randbytes,
    socket_set_linger,
)
from .validator import TcpAuthValidator, TcpAuthValidatorKey

logger = logging.getLogger(__name__)


def add_connection_info(
    tracker: TCPConnectionTracker,
    saddr,
    daddr,
    sport,
    dport,
    sisn,
    disn,
):
    client2server_key = TCPConnectionKey(
        saddr=saddr,
        daddr=daddr,
        sport=sport,
        dport=dport,
    )
    client2server_conn = tracker.get_or_create(client2server_key)
    client2server_conn.sisn = sisn
    client2server_conn.disn = disn
    client2server_conn.snd_sne.reset(sisn)
    client2server_conn.rcv_sne.reset(disn)
    client2server_conn.found_syn = True
    client2server_conn.found_synack = True
    server2client_conn = tracker.get_or_create(client2server_key.rev())
    server2client_conn.sisn = disn
    server2client_conn.disn = sisn
    server2client_conn.snd_sne.reset(disn)
    server2client_conn.rcv_sne.reset(sisn)
    server2client_conn.found_syn = True
    server2client_conn.found_synack = True


@pytest.mark.parametrize("signed", [False, True])
def test_high_seq_rollover(exit_stack: ExitStack, signed: bool):
    """Test SNE by rolling over from a high seq/ack value

    Create many connections until a very high seq/ack is found and then transfer
    enough for those values to roll over.

    A side effect of this approach is that this stresses connection
    establishment.
    """
    address_family = socket.AF_INET
    overflow = 0x200000
    bufsize = 0x10000
    secret_key = b"12345"
    mode = "echo"
    validator_enabled = True
    tcp_repair_authopt_enabled = True
    fail = False

    nsfixture = exit_stack.enter_context(NamespaceFixture())
    server_addr = nsfixture.get_addr(address_family, 1)
    client_addr = nsfixture.get_addr(address_family, 2)
    server_addr_port = (str(server_addr), DEFAULT_TCP_SERVER_PORT)
    listen_socket = create_listen_socket(
        ns=nsfixture.server_netns_name,
        family=address_family,
        bind_addr=server_addr,
        listen_depth=1024,
    )
    exit_stack.enter_context(listen_socket)
    if signed:
        set_tcp_authopt_key_kwargs(listen_socket, key=secret_key)
    server_thread = SimpleServerThread(listen_socket, mode=mode, bufsize=bufsize)
    exit_stack.enter_context(server_thread)

    found = False
    client_socket = None
    for iternum in range(50000):
        try:
            # Manually assign increasing client ports
            #
            # Sometimes linux kills timewait sockets (TCPTimeWaitOverflow) and
            # then attempts to reuse the port. The stricter validation
            # requirements of TCP-AO mean the other side of the socket survives
            # and rejects packets coming from the reused port.
            #
            # This issue is not related to SNE so a workaround is acceptable.
            client_socket = create_client_socket(
                ns=nsfixture.client_netns_name,
                family=address_family,
                bind_addr=client_addr,
                bind_port=10000 + iternum,
            )
            if signed:
                set_tcp_authopt_key_kwargs(client_socket, key=secret_key)
            try:
                client_socket.connect(server_addr_port)
            except:
                logger.error("failed connect on iteration %d", iternum, exc_info=True)
                raise

            recv_seq, send_seq = get_tcp_repair_recv_send_queue_seq(client_socket)
            if (recv_seq + overflow > 0x100000000 and mode == "echo") or (
                send_seq + overflow > 0x100000000
            ):
                found = True
                break
            # Wait for graceful close to avoid swamping server listen queue.
            # This makes the test work even with a server listen_depth=1 but set
            # a very high value anyway.
            socket_set_linger(client_socket, 1, 1)
            client_socket.close()
            client_socket = None
        finally:
            if not found and client_socket:
                client_socket.close()
    assert found
    assert client_socket is not None

    logger.debug("setup recv_seq %08x send_seq %08x", recv_seq, send_seq)

    # Init tcp_repair_authopt
    if signed and tcp_repair_authopt_enabled:
        with tcp_repair_toggle(client_socket):
            init_tcp_repair_authopt = get_tcp_repair_authopt(client_socket)
        assert init_tcp_repair_authopt.src_isn + 1 == send_seq
        assert init_tcp_repair_authopt.dst_isn + 1 == recv_seq
        assert init_tcp_repair_authopt.snd_sne == 0
        assert init_tcp_repair_authopt.rcv_sne == 0
        logger.debug("tcp repair authopt: %r", init_tcp_repair_authopt)

    # Init validator
    if signed and validator_enabled:
        capture_filter = f"tcp port {DEFAULT_TCP_SERVER_PORT}"
        capture_socket = create_capture_socket(
            ns=nsfixture.client_netns_name,
            iface="veth0",
            filter=capture_filter,
        )
        sniffer = exit_stack.enter_context(
            AsyncSnifferContext(opened_socket=capture_socket)
        )
        validator = TcpAuthValidator()
        validator.keys.append(
            TcpAuthValidatorKey(key=secret_key, alg_name="HMAC-SHA-1-96")
        )
        # validator.debug_sne = True
        # validator.log_traffic_key = True
        # validator.log_mac = True

        # SYN+SYNACK is not captured so initialize connection info manually
        add_connection_info(
            validator.tracker,
            saddr=ip_address(client_addr),
            daddr=ip_address(server_addr),
            dport=client_socket.getpeername()[1],
            sport=client_socket.getsockname()[1],
            sisn=tcp_seq_wrap(send_seq - 1),
            disn=tcp_seq_wrap(recv_seq - 1),
        )

    transfer_iter_count = 2 * overflow // bufsize
    logger.info(
        "transfer %d bytes in %d iterations",
        2 * overflow,
        transfer_iter_count,
    )
    for iternum in range(transfer_iter_count):
        try:
            if mode == "recv":
                from .utils import randbytes

                send_buf = randbytes(bufsize)
                client_socket.sendall(send_buf)
            else:
                check_socket_echo(client_socket, bufsize)
        except:
            logger.error("failed traffic on iteration %d", iternum, exc_info=True)
            fail = True
            break

    new_recv_seq, new_send_seq = get_tcp_repair_recv_send_queue_seq(client_socket)
    logger.debug("final recv_seq %08x send_seq %08x", new_recv_seq, new_send_seq)
    if not (new_recv_seq < recv_seq or new_send_seq < send_seq):
        fail = True

    # Validate capture
    if signed and validator_enabled:
        import time

        time.sleep(1)
        sniffer.stop()
        for p in sniffer.results:
            validator.handle_packet(p)
        # Allow incomplete connections from FIN/ACK of connections dropped
        # because of low seq/ack
        # validator.raise_errors(allow_incomplete=True)
        if validator.any_fail or validator.any_unsigned:
            fail = True
        client_scappy_key = TCPConnectionKey(
            saddr=ip_address(client_addr),
            daddr=ip_address(server_addr),
            dport=client_socket.getpeername()[1],
            sport=client_socket.getsockname()[1],
        )
        client_scappy_conn = validator.tracker.get(client_scappy_key)
        snd_sne_rollover = client_scappy_conn.snd_sne.sne != 0
        rcv_sne_rollover = client_scappy_conn.rcv_sne.sne != 0
        if not (snd_sne_rollover or rcv_sne_rollover):
            logger.error("expected either snd_snd or rcv_sne to rollover")
            fail = True

    # Validate SNE as read via TCP_REPAIR_AUTHOPT
    if signed and tcp_repair_authopt_enabled:
        with tcp_repair_toggle(client_socket):
            exit_tcp_repair_authopt = get_tcp_repair_authopt(client_socket)
        logger.debug("exit tcp repair authopt: %r", exit_tcp_repair_authopt)
        assert exit_tcp_repair_authopt.src_isn == init_tcp_repair_authopt.src_isn
        assert exit_tcp_repair_authopt.dst_isn == init_tcp_repair_authopt.dst_isn
        if not (exit_tcp_repair_authopt.snd_sne or exit_tcp_repair_authopt.rcv_sne):
            logger.error("expected either snd_snd or rcv_sne to rollover")
            fail = True

    assert not fail


def _block_client_tcp(nsfixture: NamespaceFixture, address_family=socket.AF_INET):
    """Prevent TCP in client namespace from sending RST

    Do this by removing the client address and inserting a static ARP on server side.
    """
    client_prefix_length = nsfixture.get_prefix_length(address_family)
    client_addr = nsfixture.get_ipv4_addr(2, 1)
    script = (
        f"""
set -e
ip netns exec {nsfixture.client_netns_name} ip addr del {client_addr}/{client_prefix_length} dev veth0
ip netns exec {nsfixture.server_netns_name} ip neigh add {client_addr} lladdr {nsfixture.client_mac_addr} dev veth0
""",
    )
    subprocess.run(script, shell=True, check=True)


@pytest.mark.parametrize("client_isn", [0xFFFF0000, 0xFFFFFFFF], ids=hex)
def test_syn_seq_ffffffff(exit_stack: ExitStack, client_isn):
    """Test SYN with seq=0xffffffff

    Client is pytest, server is linux.
    """
    con = TCPConnectionFixture()
    con.tcp_authopt_key = tcp_authopt_key(
        alg=TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
        key=b"hello",
    )
    exit_stack.enter_context(con)

    client_l2socket = con.client_l2socket
    server_isn = 0
    DEFAULT_BUFSIZE = 1000

    def sign(packet, sne=0):
        add_tcp_authopt_signature(
            packet,
            TcpAuthOptAlg_HMAC_SHA1(),
            con.tcp_authopt_key.key,
            client_isn,
            server_isn,
            sne=sne,
        )

    _block_client_tcp(con.nsfixture)

    # send SYN
    p = con.create_client2server_packet()
    p[TCP].flags = "S"
    p[TCP].seq = client_isn
    p[TCP].ack = 0
    sign(p)
    client_l2socket.send(p)

    # wait SYN/ACK
    def has_synack():
        return (
            con.sniffer_session.client_info is not None
            and con.sniffer_session.client_info.disn is not None
        )

    waiting.wait(has_synack, timeout_seconds=5, sleep_seconds=0.1)
    server_isn = con.sniffer_session.client_info.disn

    # send ACK to SYN/ACK
    p = con.create_client2server_packet()
    p[TCP].flags = "A"
    p[TCP].seq = tcp_seq_wrap(client_isn + 1)
    p[TCP].ack = tcp_seq_wrap(server_isn + 1)
    sign(p, sne=(client_isn + 1) >> 32)
    client_l2socket.send(p)

    # send data
    p = con.create_client2server_packet()
    p[TCP].flags = "PA"
    p[TCP].seq = tcp_seq_wrap(client_isn + 1)
    p[TCP].ack = tcp_seq_wrap(server_isn + 1)
    p /= Raw(randbytes(DEFAULT_BUFSIZE))
    sign(p, sne=(client_isn + 1) >> 32)
    client_l2socket.send(p)

    def has_response():
        con.assert_no_snmp_output_failures()
        plist = con.sniffer_session.toPacketList()
        logger.info("sniffer list:\n%s", plist)
        for p in plist:
            logger.info("p %s len %d", p.summary(), len(p))
            th = p.getlayer(TCP)
            if not th:
                continue
            logger.info("th %s len %d", p.summary(), len(th.payload))
            if th.sport != DEFAULT_TCP_SERVER_PORT:
                continue
            th_end_seq = th.seq + len(th.payload)
            logger.info(
                "th_end_seq %08x versus server_isn %08x", th_end_seq, server_isn
            )
            if th_end_seq - server_isn >= DEFAULT_BUFSIZE:
                logger.info("packet %s looks like a server response", th.summary())
                return True
        return False

    waiting.wait(has_response, timeout_seconds=5, sleep_seconds=1)


def _block_server_tcp(nsfixture: NamespaceFixture, address_family=socket.AF_INET):
    splen = nsfixture.get_prefix_length(address_family)
    saddr = nsfixture.get_ipv4_addr(1, 1)
    script = (
        f"""
set -e
ip netns exec {nsfixture.server_netns_name} ip addr del {saddr}/{splen} dev veth0
ip netns exec {nsfixture.client_netns_name} ip neigh add {saddr} lladdr {nsfixture.server_mac_addr} dev veth0
""",
    )
    subprocess.run(script, shell=True, check=True)


@pytest.mark.parametrize("server_isn", [0xFFFF0000, 0xFFFFFFFF], ids=hex)
def test_synack_seq_ffffffff(exit_stack: ExitStack, server_isn: int):
    """Test SYNACK with seq=0xffffffff

    Verifies linux client behavior against a server that sends SYNACK with seq=0xffffffff
    """
    con = TCPConnectionFixture(capture_on_client=True)
    con.tcp_authopt_key = tcp_authopt_key(
        alg=TCP_AUTHOPT_ALG.HMAC_SHA_1_96,
        key=b"hello",
    )
    exit_stack.enter_context(con)
    sniffer_session = con.sniffer_session

    server_l2socket = con.server_l2socket
    client_isn = 0

    def sign(packet, sne=0):
        add_tcp_authopt_signature(
            packet,
            TcpAuthOptAlg_HMAC_SHA1(),
            con.tcp_authopt_key.key,
            server_isn,
            client_isn,
            sne=sne,
        )

    _block_server_tcp(con.nsfixture)

    def run_client_thread():
        # If this fails it will likely be with a timeout
        logger.info("client connect call")
        con.client_socket.connect(con.server_addr_port)
        logger.info("client connect done")

    client_thread = ExThread(target=run_client_thread)
    client_thread.start()

    # wait SYN
    def has_recv_syn():
        return (
            con.sniffer_session.server_info is not None
            and con.sniffer_session.server_info.disn is not None
        )

    waiting.wait(has_recv_syn, timeout_seconds=5, sleep_seconds=0.1)
    client_isn = sniffer_session.server_info.disn
    logger.info("Received SYN with SEQ=%d", client_isn)

    # craft SYN/ACK
    p = con.create_server2client_packet()
    p[TCP].flags = "SA"
    p[TCP].seq = server_isn
    p[TCP].ack = tcp_seq_wrap(client_isn + 1)
    sign(p)
    server_l2socket.send(p)

    def is_client_ack(p: Packet):
        th = p.getlayer(TCP)
        if not th:
            return False
        if not sniffer_session.server_info.is_recv_match(p):
            return False
        if th.flags.A and th.ack == tcp_seq_wrap(server_isn + 1):
            check_tcp_authopt_signature(
                p,
                TcpAuthOptAlg_HMAC_SHA1(),
                con.tcp_authopt_key.key,
                client_isn,
                server_isn,
                sne=(server_isn + 1) >> 32,
            )
            return True
        return False

    def sniffer_has_packet(pred):
        for p in sniffer_session.lst:
            if pred(p):
                return True
        return False

    def has_client_ack():
        return sniffer_has_packet(is_client_ack)

    waiting.wait(has_client_ack, timeout_seconds=5, sleep_seconds=0.1)

    # No attempt is made to transfer data

    # Will raise any errors from client_thread_run
    client_thread.join()
