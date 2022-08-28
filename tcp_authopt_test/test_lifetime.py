import socket
import time
from datetime import datetime, timedelta, timezone

import pytest

from .linux_tcp_authopt import get_tcp_authopt, tcp_authopt_key
from .test_rollover import make_tcp_authopt_socket_pair
from .utils import check_socket_echo


def test_basic():
    t0 = datetime.now(timezone.utc)
    td_float = 2.0
    td = timedelta(seconds=td_float)
    #
    # TIME:     -2  -1  0   1   2   3   4   5   6
    # K1:       N   Y   Y   Y   Y   Y   N   N   N
    # K2:       N   N   N   Y   Y   Y   Y   Y   N
    #
    k1_stime = t0 - td
    k1_etime = t0 + 3 * td
    k2_stime = t0 + td
    k2_etime = t0 + 5 * td
    k1 = tcp_authopt_key(
        send_id=1,
        recv_id=1,
        key="111",
        send_lifetime_begin=k1_stime,
        send_lifetime_end=k1_etime,
        recv_lifetime_begin=k1_stime,
        recv_lifetime_end=k1_etime,
    )
    k2 = tcp_authopt_key(
        send_id=2,
        recv_id=2,
        key="222",
        send_lifetime_begin=k2_stime,
        send_lifetime_end=k2_etime,
        recv_lifetime_begin=k2_stime,
        recv_lifetime_end=k2_etime,
    )
    context = make_tcp_authopt_socket_pair(
        server_key_list=[k1, k2], client_key_list=[k1, k2]
    )
    with context as (client_socket, server_socket):
        check_socket_echo(client_socket)
        server_info = get_tcp_authopt(server_socket)
        client_info = get_tcp_authopt(client_socket)
        assert (
            server_info.send_keyid == 1
            and server_info.send_rnextkeyid == 1
            and client_info.send_keyid == 1
            and client_info.send_rnextkeyid == 1
        )

        # At T=2 K1 is still valid but both have switched to K2
        time.sleep(td_float)
        check_socket_echo(client_socket)
        time.sleep(td_float)
        check_socket_echo(client_socket)
        server_info = get_tcp_authopt(server_socket)
        client_info = get_tcp_authopt(client_socket)
        assert (
            server_info.send_keyid == 2
            and server_info.send_rnextkeyid == 2
            and client_info.send_keyid == 2
            and client_info.send_rnextkeyid == 2
        )

        # At T=4 K1 is invalid but K2 work
        time.sleep(td_float)
        check_socket_echo(client_socket)
        time.sleep(td_float)
        check_socket_echo(client_socket)

        # At T=5 K2 expires and at T=6 we are definitely out of luck
        with pytest.raises(socket.timeout):
            time.sleep(td_float)
            check_socket_echo(client_socket)
            time.sleep(td_float)
            check_socket_echo(client_socket)
