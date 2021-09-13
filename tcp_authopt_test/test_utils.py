import pytest
from . import utils


def test_scapy_tcp_seq_rollover():
    """In case anybody wondered scapy does not in fact automate seq rollover"""
    from scapy.layers.inet import IP, TCP

    p = IP() / TCP()
    p[TCP].seq = 0xA0000000 + 0x70000000
    assert (hex(p[TCP].seq) == "0x110000000")
    assert (p[TCP].seq == 0x110000000)
    p[TCP].seq = 0xffffff00
    assert (hex(p[TCP].seq) == "0xffffff00")
    p[TCP].seq += 0x101
    assert (hex(p[TCP].seq) == "0x100000001")

    with pytest.raises(Exception):
        TCP(bytes(p[TCP]))


def test_tcp_seq_wrap():
    assert hex(utils.tcp_seq_wrap(0xA0000000 + 0x70000000)) == "0x10000000"
    assert hex(utils.tcp_seq_wrap(10 - 12)) == "0xfffffffe"
