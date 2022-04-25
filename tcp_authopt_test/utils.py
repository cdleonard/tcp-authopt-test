# SPDX-License-Identifier: GPL-2.0
import json
import random
import socket
import subprocess
import typing
from contextlib import nullcontext

from nsenter import Namespace

# TCP port does not impact Authentication Option so define a single default
DEFAULT_TCP_SERVER_PORT = 17971


def recvall(sock, todo):
    """Receive exactly todo bytes unless EOF"""
    data = bytes()
    while True:
        chunk = sock.recv(todo)
        if not len(chunk):
            return data
        data += chunk
        todo -= len(chunk)
        if todo == 0:
            return data
        assert todo > 0


def sendall_checked(sock: socket.socket, buf: bytes):
    """Like socket.sendall but with more checks.

    Check that return value from send() is not more than the length of the
    buffer passed in, which indicates a serious kernel issue.
    """
    pos = 0
    while pos < len(buf):
        ret = sock.send(buf[pos:])
        if ret > len(buf) - pos:
            raise ValueError(f"socket send returned {ret} for buf len {len(buf) - pos}")
        # Python should handle errors
        if ret <= 0:
            raise ValueError(f"socket send returned {ret} unexpected")
        pos += ret



def randbytes(count) -> bytes:
    """Return a random byte array"""
    return bytes([random.randint(0, 255) for index in range(count)])


def check_socket_echo(sock: socket.socket, size=1000, checked=True):
    """Send random bytes and check they are received

    The default size is equal to `SimpleServerThread.DEFAULT_BUFSIZE` which
    means that a single pair of packets will be sent at the TCP level.
    """
    send_buf = randbytes(size)
    if checked:
        sendall_checked(sock, send_buf)
    else:
        sock.sendall(send_buf)
    recv_buf = recvall(sock, size)
    assert send_buf == recv_buf


def nstat_json(command_prefix: str = "", namespace=None):
    """Parse nstat output into a python dict"""
    if namespace is not None:
        command_prefix += f"ip netns exec {namespace} "
    runres = subprocess.run(
        f"{command_prefix}nstat -a --zeros --json",
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )
    return json.loads(runres.stdout)["kernel"]


def netns_context(ns: str = ""):
    """Create context manager for a certain optional netns

    If the ns argument is empty then just return a `nullcontext`
    """
    if ns:
        return Namespace("/var/run/netns/" + ns, "net")
    else:
        return nullcontext()


def socket_set_bindtodevice(sock, dev: str):
    """Set SO_BINDTODEVICE"""
    opt = dev.encode("utf-8") + b"\0"
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, opt)


def create_listen_socket(
    ns: str = "",
    family=socket.AF_INET,
    reuseaddr=True,
    listen_depth=10,
    bind_addr="",
    bind_port=DEFAULT_TCP_SERVER_PORT,
    bind_device: typing.Optional[str] = None,
):
    with netns_context(ns):
        listen_socket = socket.socket(family, socket.SOCK_STREAM)
    if reuseaddr:
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if bind_device:
        socket_set_bindtodevice(listen_socket, bind_device)
    listen_socket.bind((str(bind_addr), bind_port))
    listen_socket.listen(listen_depth)
    return listen_socket


def create_client_socket(
    ns: str = "", family=socket.AF_INET, bind_addr="", bind_port=0, timeout=1.0
):
    with netns_context(ns):
        client_socket = socket.socket(family, socket.SOCK_STREAM)
    if bind_addr or bind_port:
        client_socket.bind((str(bind_addr), bind_port))
    if timeout is not None:
        client_socket.settimeout(timeout)
    return client_socket


def socket_set_linger(sock, onoff, value):
    import struct

    sock.setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", int(onoff), int(value))
    )
