"""Python translation of https://datatracker.ietf.org/doc/draft-touch-sne/"""

from .sne_alg import SequenceNumberExtender


def test_sne_alg():
    alg = SequenceNumberExtender()
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
        observed_sne = alg.calc(seq)
        assert observed_sne == sne
