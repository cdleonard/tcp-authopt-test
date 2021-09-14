# SPDX-License-Identifier: GPL-2.0
"""Test TCP_AUTHOPT sockopt API"""
import errno
import socket
import struct
from ipaddress import IPv4Address, IPv6Address

import pytest

from . import linux_tcp_authopt
from .linux_tcp_authopt import (
    TCP_AUTHOPT,
    set_tcp_authopt,
    get_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .sockaddr import sockaddr_unpack
from .conftest import skipif_missing_tcp_authopt

pytestmark = skipif_missing_tcp_authopt


def test_authopt_key_pack_noaddr():
    b = bytes(tcp_authopt_key(key=b"a\x00b"))
    assert b[7] == 3
    assert b[8:13] == b"a\x00b\x00\x00"


def test_authopt_key_pack_addr():
    b = bytes(tcp_authopt_key(key=b"a\x00b", addr="10.0.0.1"))
    assert struct.unpack("H", b[88:90])[0] == socket.AF_INET
    assert sockaddr_unpack(b[88:]).addr == IPv4Address("10.0.0.1")


def test_authopt_key_pack_addr6():
    b = bytes(tcp_authopt_key(key=b"abc", addr="fd00::1"))
    assert struct.unpack("H", b[88:90])[0] == socket.AF_INET6
    assert sockaddr_unpack(b[88:]).addr == IPv6Address("fd00::1")


def test_tcp_authopt_key_del_without_active(exit_stack):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exit_stack.push(sock)

    # nothing happens:
    key = tcp_authopt_key()
    assert key.delete_flag is False
    key.delete_flag = True
    assert key.delete_flag is True
    with pytest.raises(OSError) as e:
        set_tcp_authopt_key(sock, key)
    assert e.value.errno in [errno.EINVAL, errno.ENOENT]


def test_tcp_authopt_key_setdel(exit_stack):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exit_stack.push(sock)
    set_tcp_authopt(sock, tcp_authopt())

    # delete returns ENOENT
    key = tcp_authopt_key()
    key.delete_flag = True
    with pytest.raises(OSError) as e:
        set_tcp_authopt_key(sock, key)
    assert e.value.errno == errno.ENOENT

    key = tcp_authopt_key(send_id=1, recv_id=2)
    set_tcp_authopt_key(sock, key)
    # First delete works fine:
    key.delete_flag = True
    set_tcp_authopt_key(sock, key)
    # Duplicate delete returns ENOENT
    with pytest.raises(OSError) as e:
        set_tcp_authopt_key(sock, key)
    assert e.value.errno == errno.ENOENT


def test_get_tcp_authopt(exit_stack):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(OSError) as e:
            sock.getsockopt(socket.SOL_TCP, TCP_AUTHOPT, 4)
        assert e.value.errno == errno.ENOENT


def test_set_get_tcp_authopt_flags(exit_stack):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # No flags by default
        set_tcp_authopt(sock, tcp_authopt())
        opt = get_tcp_authopt(sock)
        assert opt.flags == 0

        # simple flags are echoed
        goodflag = linux_tcp_authopt.TCP_AUTHOPT_FLAG.REJECT_UNEXPECTED
        set_tcp_authopt(sock, tcp_authopt(flags=goodflag))
        opt = get_tcp_authopt(sock)
        assert opt.flags == goodflag

        # attempting to set a badflag returns an error and has no effect
        badflag = 1 << 27
        with pytest.raises(OSError) as e:
            set_tcp_authopt(sock, tcp_authopt(flags=badflag))
        opt = get_tcp_authopt(sock)
        assert opt.flags == goodflag
