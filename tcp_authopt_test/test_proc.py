import logging
import socket
import subprocess
import typing
from contextlib import ExitStack, contextmanager

import pytest

from .linux_tcp_authopt import del_tcp_authopt_key, set_tcp_authopt_key, tcp_authopt_key
from .linux_tcp_authopt_proc import (
    has_proc_tcp_authopt,
    read_proc_tcp_authopt_keys_as_lines,
)
from .utils import netns_context

logger = logging.getLogger(__name__)


@contextmanager
def temp_netns() -> typing.Iterator[str]:
    netns_name = "tcp_authopt_test"
    subprocess.run(f"ip netns add {netns_name}", check=True, shell=True)
    try:
        yield netns_name
    finally:
        subprocess.run(f"ip netns del {netns_name}", check=True, shell=True)


skipif_missing_proc_tcp_authopt = pytest.mark.skipif(
    not has_proc_tcp_authopt(), reason="Missing /proc/net/tcp_authopt feature"
)


@skipif_missing_proc_tcp_authopt
def test_one_proc_key(exit_stack: ExitStack):
    netns_name = exit_stack.enter_context(temp_netns())
    with netns_context(netns_name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        exit_stack.enter_context(sock)

    proc_lines = read_proc_tcp_authopt_keys_as_lines(netns_name)
    assert len(proc_lines) == 0

    set_tcp_authopt_key(sock, tcp_authopt_key(send_id=12, recv_id=23))
    proc_lines = read_proc_tcp_authopt_keys_as_lines(netns_name)
    assert len(proc_lines) == 1
    assert proc_lines[0] == "0\t12\t23\t*"

    set_tcp_authopt_key(sock, tcp_authopt_key(send_id=100, recv_id=100))
    proc_lines = sorted(read_proc_tcp_authopt_keys_as_lines(netns_name))
    assert len(proc_lines) == 2
    assert proc_lines[0] == "0\t100\t100\t*"
    assert proc_lines[1] == "0\t12\t23\t*"

    del_tcp_authopt_key(sock, tcp_authopt_key(send_id=12, recv_id=23))
    proc_lines = sorted(read_proc_tcp_authopt_keys_as_lines(netns_name))
    assert len(proc_lines) == 1
    assert proc_lines[0] == "0\t100\t100\t*"


@skipif_missing_proc_tcp_authopt
def test_verify_leak(exit_stack: ExitStack):
    netns_name = exit_stack.enter_context(temp_netns())
    with netns_context(netns_name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        exit_stack.enter_context(sock)

    from .linux_tcp_authopt_proc import verify_global_key_leak

    k = tcp_authopt_key(send_id=12, recv_id=23)
    with pytest.raises(Exception, match="Leaked keys"):
        with verify_global_key_leak(netns_name):
            set_tcp_authopt_key(sock, k)
    del_tcp_authopt_key(sock, k)
