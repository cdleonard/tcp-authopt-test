import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from .scapy_utils import tcp_seq_wrap


def test_scapy_tcp_seq_rollover():
    """In case anybody wondered scapy does not in fact automate seq rollover"""

    p = IP() / TCP()
    p[TCP].seq = 0xA0000000 + 0x70000000
    assert hex(p[TCP].seq) == "0x110000000"
    assert p[TCP].seq == 0x110000000
    p[TCP].seq = 0xFFFFFF00
    assert hex(p[TCP].seq) == "0xffffff00"
    p[TCP].seq += 0x101
    assert hex(p[TCP].seq) == "0x100000001"

    with pytest.raises(Exception):
        TCP(bytes(p[TCP]))


def test_tcp_seq_wrap():
    assert hex(tcp_seq_wrap(0xA0000000 + 0x70000000)) == "0x10000000"
    assert hex(tcp_seq_wrap(10 - 12)) == "0xfffffffe"


def test_sign_tcp_authopt():
    from .scapy_tcp_authopt import TcpAuthOptAlg_HMAC_SHA1
    from .scapy_tcp_authopt import add_tcp_authopt_signature
    from .scapy_tcp_authopt import check_tcp_authopt_signature
    from .scapy_tcp_authopt import break_tcp_authopt_signature

    alg = TcpAuthOptAlg_HMAC_SHA1()
    master_key = b"secret"
    sisn = 1000
    disn = 0

    p = Ether() / IP() / TCP(flags="S", seq=sisn, ack=disn)
    add_tcp_authopt_signature(p, alg, master_key, sisn, disn)
    assert check_tcp_authopt_signature(p, alg, master_key, sisn, disn)

    p1bytes = bytes(p)
    break_tcp_authopt_signature(p)
    p2bytes = bytes(p)
    assert not check_tcp_authopt_signature(p, alg, master_key, sisn, disn)
    assert Ether(p1bytes)[TCP].chksum != Ether(p2bytes)[TCP].chksum


def test_calc_tcp_md5_hash_value():
    """Test the hash computation"""
    from .scapy_utils import calc_tcp_md5_hash

    key = b"12345"

    p = IP() / TCP()
    print(bytes(p).hex())
    mac = calc_tcp_md5_hash(p[TCP], key)
    assert mac.hex() == "797e69f8dbe44a8b84f687a2832595ed"

    p = IPv6() / TCP()
    print(bytes(p).hex())
    mac = calc_tcp_md5_hash(p[TCP], key)
    assert mac.hex() == "3711309b0305a4269ec5dbc27183e9a0"
