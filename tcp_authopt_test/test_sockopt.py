# SPDX-License-Identifier: GPL-2.0
"""Test TCP_AUTHOPT sockopt API"""
import errno
import socket
import struct
from ipaddress import IPv4Address, IPv6Address

import pytest

from .conftest import skipif_missing_tcp_authopt
from .linux_tcp_authopt import (
    TCP_AUTHOPT,
    TCP_AUTHOPT_ALG,
    TCP_AUTHOPT_FLAG,
    TCP_AUTHOPT_KEY,
    TCP_AUTHOPT_KEY_FLAG,
    del_tcp_authopt_key,
    get_tcp_authopt,
    set_tcp_authopt,
    set_tcp_authopt_key,
    tcp_authopt,
    tcp_authopt_key,
)
from .sockaddr import sockaddr_unpack

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
    """Test attempting to delete a missing key"""
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
    """Test adding and then removing a key"""
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


def test_get_tcp_authopt():
    """Doing getsockopt TCP_AUTHOPT on a new socket returns ENOENT by default"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(OSError) as e:
            sock.getsockopt(socket.SOL_TCP, TCP_AUTHOPT, 4)
        assert e.value.errno == errno.ENOENT


def test_set_get_tcp_authopt_flags():
    """Check read/write to tcp_authopt.flags"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # No flags by default
        set_tcp_authopt(sock, tcp_authopt())
        opt = get_tcp_authopt(sock)
        assert opt.flags == 0

        # simple flags are echoed
        goodflag = TCP_AUTHOPT_FLAG.REJECT_UNEXPECTED
        set_tcp_authopt(sock, tcp_authopt(flags=goodflag))
        opt = get_tcp_authopt(sock)
        assert opt.flags == goodflag

        # attempting to set a bad flag returns an error and has no effect
        badflag = 1 << 27
        with pytest.raises(OSError) as e:
            set_tcp_authopt(sock, tcp_authopt(flags=badflag))
        opt = get_tcp_authopt(sock)
        assert opt.flags == goodflag


def test_set_ipv6_key_on_ipv4():
    """Binding a key to an ipv6 address on an ipv4 socket is an error"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        key = tcp_authopt_key(key="abc")
        key.flags = TCP_AUTHOPT_KEY_FLAG.BIND_ADDR
        key.addr = IPv6Address("::1234")
        with pytest.raises(OSError):
            set_tcp_authopt_key(sock, key)


def test_set_ipv4_key_on_ipv6():
    """This could be implemented for ipv6-mapped-ipv4 but it is not

    TCP_MD5SIG has a similar limitation
    """
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
        key = tcp_authopt_key(key="abc")
        key.flags = TCP_AUTHOPT_KEY_FLAG.BIND_ADDR
        key.addr = IPv4Address("1.2.3.4")
        with pytest.raises(OSError):
            set_tcp_authopt_key(sock, key)


def test_authopt_key_badflags():
    """Unknown flags on tcp_authopt_key produce errors"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        with pytest.raises(OSError):
            set_tcp_authopt_key(
                sock,
                tcp_authopt_key(flags=TCP_AUTHOPT_KEY_FLAG(0xABCDEF)),
            )


def test_authopt_key_longer_bad():
    """Test that passing a longer sockopt with unknown data fails

    Old kernels won't pretend to handle features they don't know about
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        key = tcp_authopt_key(alg=TCP_AUTHOPT_ALG.HMAC_SHA_1_96, key="aaa")
        optbuf = bytes(key)
        optbuf = optbuf.ljust(len(optbuf) + 256, b"\x5a")
        with pytest.raises(OSError):
            sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT_KEY, optbuf)


def test_authopt_key_longer_zeros():
    """Test that passing a longer sockopt padded with zeros works

    This ensures applications using a larger struct tcp_authopt_key won't have
    to pass a shorter optlen on old kernels.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        key = tcp_authopt_key(alg=TCP_AUTHOPT_ALG.HMAC_SHA_1_96, key="aaa")
        optbuf = bytes(key)
        optbuf = optbuf.ljust(len(optbuf) + 256, b"\x00")
        sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT_KEY, optbuf)
        # the key was added and can be deleted normally
        assert del_tcp_authopt_key(sock, key) == True
        assert del_tcp_authopt_key(sock, key) == False


def test_authopt_longer_baddata():
    """Test passing a long tcp_authopt sockopt with unknown data fails"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        opt = tcp_authopt()
        optbuf = bytes(opt)
        optbuf = optbuf.ljust(len(optbuf) + 256, b"\x5a")
        with pytest.raises(OSError):
            sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT, optbuf)


def test_authopt_longer_zeros():
    """Test passing a long tcp_authopt sockopt with zeros fails"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        opt = tcp_authopt()
        optbuf = bytes(opt)
        optbuf = optbuf.ljust(len(optbuf) + 256, b"\x00")
        sock.setsockopt(socket.SOL_TCP, TCP_AUTHOPT, optbuf)


def test_authopt_setdel_addrbind():
    """Test matching address on key delete"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        key = tcp_authopt_key(addr="1.1.1.1", recv_id=1, send_id=1)
        key2 = tcp_authopt_key(addr="1.1.1.2", recv_id=1, send_id=1)
        set_tcp_authopt_key(sock, key)
        assert del_tcp_authopt_key(sock, key2) == False
        assert del_tcp_authopt_key(sock, key) == True
        assert del_tcp_authopt_key(sock, key) == False


def test_authopt_include_options():
    """Test the treatment of `tcp_authopt_key.include_options`"""
    key = tcp_authopt_key()
    assert key.include_options
    key.include_options = False
    assert key.flags & TCP_AUTHOPT_KEY_FLAG.EXCLUDE_OPTS
    assert not key.include_options


def test_optmem():
    """Test the treatment of `tcp_authopt_key.include_options`"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        for _ in range(10000):
            key = tcp_authopt_key(addr="1.1.1.1", recv_id=1, send_id=1)
            set_tcp_authopt_key(sock, key)
            assert del_tcp_authopt_key(sock, key) == True
