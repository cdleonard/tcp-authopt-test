"""Test SNE algorithm implementations"""

import pytest
from .sne_alg import SequenceNumberExtender
from .sne_alg import SequenceNumberExtenderRFC
import logging

logger = logging.getLogger(__name__)


def _sne_test_data():
    """Test data from https://datatracker.ietf.org/doc/draft-touch-sne/"""
    val = """
00000000 00000000
00000000 30000000
00000000 90000000
00000000 70000000
00000000 a0000000
00000001 00000001
00000000 e0000000
00000001 00000000
00000001 7fffffff
00000001 00000000
00000001 50000000
00000001 80000000
00000001 00000001
00000001 40000000
00000001 90000000
00000001 b0000000
00000002 0fffffff
00000002 20000000
00000002 90000000
00000002 70000000
00000002 A0000000
00000003 00004000
00000002 D0000000
00000003 20000000
00000003 90000000
00000003 70000000
00000003 A0000000
00000004 00004000
00000003 D0000000
"""
    for item in val.splitlines():
        item = item.strip()
        if not item:
            continue
        sne_hex, seq_hex = item.split()
        sne = int(sne_hex, 16)
        seq = int(seq_hex, 16)
        yield sne, seq


# Easier test data with small jumps <= 0x30000000
SNE_DATA_EASY = [
    (0x00000000, 0x00000000),
    (0x00000000, 0x30000000),
    (0x00000000, 0x60000000),
    (0x00000000, 0x80000000),
    (0x00000000, 0x90000000),
    (0x00000000, 0xC0000000),
    (0x00000000, 0xF0000000),
    (0x00000001, 0x10000000),
    (0x00000000, 0xF0030000),
    (0x00000001, 0x00030000),
    (0x00000001, 0x10030000),
]


def check_sne_alg(alg, data):
    for sne, seq in data:
        observed_sne = alg.calc(seq)
        logger.info(
            "seq %08x expected sne %08x observed sne %08x", seq, sne, observed_sne
        )
        assert observed_sne == sne


def test_sne_alg():
    check_sne_alg(SequenceNumberExtender(), _sne_test_data())


def test_sne_alg_easy():
    check_sne_alg(SequenceNumberExtender(), SNE_DATA_EASY)


@pytest.mark.xfail
def test_sne_alg_rfc():
    check_sne_alg(SequenceNumberExtenderRFC(), _sne_test_data())


@pytest.mark.xfail
def test_sne_alg_rfc_easy():
    check_sne_alg(SequenceNumberExtenderRFC(), SNE_DATA_EASY)
