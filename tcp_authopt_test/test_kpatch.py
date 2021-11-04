import os
import socket
import subprocess
from contextlib import ExitStack, suppress

import pytest

from .linux_tcp_authopt import has_tcp_authopt, set_tcp_authopt_key, tcp_authopt_key
from .server import SimpleServerThread
from .utils import (
    DEFAULT_TCP_SERVER_PORT,
    check_socket_echo,
    create_client_socket,
    create_listen_socket,
)

KPATCH_NAME = "tcp_authopt"
KPATCH_PATH = f"/tmp/livepatch-{KPATCH_NAME}.ko"
KPATCH_LIST_NAME = f"livepatch_{KPATCH_NAME}"


def is_kpatch_loaded():
    return subprocess.call(f"kpatch list|grep {KPATCH_NAME}", shell=True) == 0


def do_kpatch_load():
    subprocess.run(f"kpatch load {KPATCH_PATH}", shell=True, check=True)


def do_kpatch_unload():
    subprocess.run(f"kpatch unload {KPATCH_LIST_NAME}", shell=True, check=True)


def test_kpatch_reload(exit_stack: ExitStack):
    """Test reloading for kpatch version of TCP_AUTHOPT"""
    if not os.path.exists(KPATCH_PATH):
        pytest.skip(f"kpatch module {KPATCH_PATH} not found")
    if not is_kpatch_loaded():
        do_kpatch_load()
    assert has_tcp_authopt()

    master_key = b"testvector"
    address_family = socket.AF_INET
    key = tcp_authopt_key(key=master_key)
    server_thread = exit_stack.enter_context(SimpleServerThread(mode="echo"))

    # Setup client/server and make traffic
    listen_socket = create_listen_socket(family=address_family)
    listen_socket = exit_stack.enter_context(listen_socket)
    set_tcp_authopt_key(listen_socket, key)
    server_thread.add_listen_socket(listen_socket)

    client_socket = create_client_socket(family=address_family)
    client_socket = exit_stack.push(client_socket)
    set_tcp_authopt_key(client_socket, key)

    client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
    for _ in range(5):
        check_socket_echo(client_socket)

    # unload kpatch during traffic, this should break the current connection but not crash the syste,
    do_kpatch_unload()

    with suppress(socket.error):
        for _ in range(5):
            check_socket_echo(client_socket)
    client_socket.close()
    server_thread.del_listen_socket(listen_socket)
    listen_socket.close()

    # reload kpatch
    do_kpatch_load()

    # try again:
    listen_socket = create_listen_socket(family=address_family)
    listen_socket = exit_stack.enter_context(listen_socket)
    set_tcp_authopt_key(listen_socket, key)
    server_thread.add_listen_socket(listen_socket)

    client_socket = create_client_socket(family=address_family)
    client_socket = exit_stack.push(client_socket)
    set_tcp_authopt_key(client_socket, key)

    client_socket.connect(("localhost", DEFAULT_TCP_SERVER_PORT))
    for _ in range(5):
        check_socket_echo(client_socket)
    client_socket.close()
