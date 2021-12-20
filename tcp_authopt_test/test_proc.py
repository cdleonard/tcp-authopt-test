import logging
import socket
import subprocess
import typing
from contextlib import ExitStack, contextmanager
from pathlib import Path

import pytest

from .linux_tcp_authopt import del_tcp_authopt_key, set_tcp_authopt_key, tcp_authopt_key
from .utils import netns_context

logger = logging.getLogger(__name__)


def has_proc_tcp_authopt() -> bool:
    return Path("/proc/net/tcp_authopt").exists()


skipif_missing_proc_tcp_authopt = pytest.mark.skipif(
    not has_proc_tcp_authopt(), reason="Missing /proc/net/tcp_authopt feature"
)


@contextmanager
def temp_netns() -> typing.Iterator[str]:
    netns_name = "tcp_authopt_test"
    subprocess.run(f"ip netns add {netns_name}", check=True, shell=True)
    try:
        yield netns_name
    finally:
        subprocess.run(f"ip netns del {netns_name}", check=True, shell=True)


def read_proc_tcp_authopt_keys_as_lines(
    netns_name: str = "",
) -> typing.Sequence[str]:
    with netns_context(netns_name):
        return Path("/proc/net/tcp_authopt").read_text().splitlines()[1:]


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
