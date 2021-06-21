import logging
from ipaddress import IPv4Address, IPv6Address
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
import struct
import hmac

logger = logging.getLogger(__name__)


def kdf_sha1(master_key: bytes, context: bytes) -> bytes:
    input = b"\x01" + b"TCP-AO" + context + b"\x00\xa0"
    return hmac.digest(master_key, input, "SHA1")


def mac_sha1(traffic_key: bytes, message: bytes) -> bytes:
    return hmac.digest(traffic_key, message, "SHA1")[:12]


def tcpao_context_vector(saddr, daddr, sport, dport, src_isn, dst_isn) -> bytes:
    return struct.pack(
        "!4s4sHHII",
        IPv4Address(saddr).packed,
        IPv4Address(daddr).packed,
        sport,
        dport,
        src_isn,
        dst_isn,
    )


def scapy_tcpao_context_vector(p: Packet, src_isn: int, dst_isn:int) -> bytes:
    return tcpao_context_vector(
        p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport, src_isn, dst_isn
    )


def scapy_tcpao_context_vector_send_syn(p: Packet) -> bytes:
    """Context for SYN"""
    return scapy_tcpao_context_vector(p, p[TCP].seq, 0)


def scapy_tcpao_context_vector_recv_syn(p: Packet) -> bytes:
    """Context for SYN/ACK"""
    return scapy_tcpao_context_vector(p, p[TCP].seq, p[TCP].ack - 1)


def scapy_tcpao_message(p: Packet, include_options=True, sne=0) -> bytearray:
    # Described by RFC5925 5.1
    result = bytearray()
    result += struct.pack("!I", sne)
    # ipv4 pseudo-header:
    result += struct.pack(
        "!4s4sHH",
        IPv4Address(p[IP].src).packed,
        IPv4Address(p[IP].dst).packed,
        6,
        p[TCP].dataofs * 4 + len(p[TCP].payload),
    )

    # tcp header with checksum set to zero
    th_bytes = bytes(p[TCP])
    result += th_bytes[:16]
    result += b"\x00\x00"
    result += th_bytes[18:20]

    # Even if include_options=False the TCP-AO option itself is still included
    # with the MAC set to all-zeros. This means we need to parse TCP options.
    pos = 20
    tcphdr_optend = p[TCP].dataofs * 4
    # logger.info("th_bytes: %s", th_bytes.hex(' '))
    assert len(th_bytes) >= tcphdr_optend
    while pos < tcphdr_optend:
        optnum = th_bytes[pos]
        pos += 1
        if optnum == 0 or optnum == 1:
            if include_options:
                result += bytes([optnum])
            continue

        optlen = th_bytes[pos]
        pos += 1
        if pos + optlen - 2 > tcphdr_optend:
            logger.info(
                "bad tcp option %d optlen %d beyond end-of-header", optnum, optlen
            )
            break
        if optlen < 2:
            logger.info("bad tcp option %d optlen %d less than two", optnum, optlen)
            break
        if optnum == 29:
            if optlen < 4:
                logger.info("bad tcp option %d optlen %d", optnum, optlen)
                break
            result += bytes([optnum, optlen])
            result += th_bytes[pos : pos + 2]
            result += (optlen - 4) * b"\x00"
        elif include_options:
            result += bytes([optnum, optlen])
            result += th_bytes[pos : pos + optlen - 2]
        pos += optlen - 2
    result += bytes(p[TCP].payload)
    return result


class TestIETFVectors:
    # https://datatracker.ietf.org/doc/html/draft-touch-tcpm-ao-test-vectors-02
    master_key = b"testvector"
    client_keyid = 61
    server_keyid = 84
    client_ipv4 = IPv4Address("10.11.12.13")
    client_ipv6 = IPv6Address("FD00::1")
    server_ipv4 = IPv4Address("172.27.28.29")
    server_ipv6 = IPv6Address("FD00::2")

    def test_4_1_1(self):
        ipv4_tcp_bytes = bytes.fromhex(
            """
            45 e0 00 4c dd 0f 40 00 ff 06 bf 6b 0a 0b 0c 0d
            ac 1b 1c 1d e9 d7 00 b3 fb fb ab 5a 00 00 00 00
            e0 02 ff ff ca c4 00 00 02 04 05 b4 01 03 03 08
            04 02 08 0a 00 15 5a b7 00 00 00 00 1d 10 3d 54
            2e e4 37 c6 f8 ed e6 d7 c4 d6 02 e7
        """
        )
        traffic_key = bytes.fromhex(
            "6d 63 ef 1b 02 fe 15 09 d4 b1 40 27 07 fd 7b 04 16 ab b7 4f"
        )
        mac = bytes.fromhex("2e e4 37 c6 f8 ed e6 d7 c4 d6 02 e7")

        p = IP(ipv4_tcp_bytes)
        assert p[IP].src == str(self.client_ipv4)
        assert p[IP].dst == str(self.server_ipv4)
        assert p[TCP].flags.S == True
        assert p[TCP].flags.A == False
        assert p[TCP].dport == 179
        assert p[TCP].sport == 0xE9D7
        assert p[TCP].ack == 0
        assert p[TCP].chksum == 0xCAC4
        assert p[TCP].dataofs == 14
        assert p[TCP].seq == 0xfbfbab5a

        context_bytes = scapy_tcpao_context_vector_send_syn(p)
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex() == traffic_key.hex()

        # message_bytes = scapy_tcpao_message(p, include_options=True)
        message_bytes = bytes.fromhex("00 00 00 00")
        message_bytes += self.client_ipv4.packed
        message_bytes += self.server_ipv4.packed
        message_bytes += bytes.fromhex("00 06 00 38")
        message_bytes += ipv4_tcp_bytes[0x14:0x24]
        message_bytes += bytes.fromhex("00 00")
        message_bytes += ipv4_tcp_bytes[0x26:0x40]
        message_bytes += b"\x00" * 12

        assert message_bytes.hex() == scapy_tcpao_message(p, include_options=True).hex()

        logger.info("message: %s", message_bytes.hex(" "))
        assert mac_sha1(traffic_key, message_bytes).hex() == mac.hex()

    def test_4_1_2(self):
        ipv4_tcp_bytes = bytes.fromhex("""\
            45 e0 00 4c 65 06 40 00 ff 06 37 75 ac 1b 1c 1d
            0a 0b 0c 0d 00 b3 e9 d7 11 c1 42 61 fb fb ab 5b
            e0 12 ff ff 37 76 00 00 02 04 05 b4 01 03 03 08
            04 02 08 0a 84 a5 0b eb 00 15 5a b7 1d 10 54 3d
            ee ab 0f e2 4c 30 10 81 51 16 b3 be
        """)
        traffic_key = bytes.fromhex(
            """d9 e2 17 e4 83 4a 80 ca 2f 3f d8 de 2e 41 b8 e6 79 7f ea 96"""
        )
        mac = bytes.fromhex("ee ab 0f e2 4c 30 10 81 51 16 b3 be")

        p = IP(ipv4_tcp_bytes)
        assert p[IP].src == str(self.server_ipv4)
        assert p[IP].sport == 179
        assert p[TCP].flags.S == True
        assert p[TCP].flags.A == True
        assert p[TCP].seq == 0x11c14261
        assert p[TCP].ack == 0xfbfbab5b
        context_bytes = scapy_tcpao_context_vector_recv_syn(p)
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex(" ") == traffic_key.hex(" ")
        message_bytes = scapy_tcpao_message(p, include_options=True)
        assert mac_sha1(traffic_key, message_bytes).hex(" ") == mac.hex(" ")

    def test_4_1_3(self):
        ipv4_tcp_bytes = bytes.fromhex("""\
            45 e0 00 87 36 a1 40 00 ff 06 65 9f 0a 0b 0c 0d
            ac 1b 1c 1d e9 d7 00 b3 fb fb ab 5b 11 c1 42 62
            c0 18 01 04 a1 62 00 00 01 01 08 0a 00 15 5a c1
            84 a5 0b eb 1d 10 3d 54 70 64 cf 99 8c c6 c3 15
            c2 c2 e2 bf ff ff ff ff ff ff ff ff ff ff ff ff
            ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d
            26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02
            00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40
            06 00 64 00 01 01 00
        """)
        traffic_key = bytes.fromhex(
            """d2 e5 9c 65 ff c7 b1 a3 93 47 65 64 63 b7 0e dc 24 a1 3d 71"""
        )
        mac = bytes.fromhex("70 64 cf 99 8c c6 c3 15 c2 c2 e2 bf")

        p = IP(ipv4_tcp_bytes)
        context_bytes = scapy_tcpao_context_vector(p, 0xfbfbab5a, 0x11c14261)
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex(" ") == traffic_key.hex(" ")
        message_bytes = scapy_tcpao_message(p, include_options=True)
        assert mac_sha1(traffic_key, message_bytes).hex(" ") == mac.hex(" ")

    def test_4_2_1(self):
        ipv4_tcp_bytes = bytes.fromhex(
            """
            45 e0 00 4c 53 99 40 00 ff 06 48 e2 0a 0b 0c 0d
            ac 1b 1c 1d ff 12 00 b3 cb 0e fb ee 00 00 00 00
            e0 02 ff ff 54 1f 00 00 02 04 05 b4 01 03 03 08
            04 02 08 0a 00 02 4c ce 00 00 00 00 1d 10 3d 54
            80 af 3c fe b8 53 68 93 7b 8f 9e c2
        """
        )
        traffic_key = bytes.fromhex(
            "30 ea a1 56 0c f0 be 57 da b5 c0 45 22 9f b1 0a 42 3c d7 ea"
        )
        mac = bytes.fromhex("80 af 3c fe b8 53 68 93 7b 8f 9e c2")

        p = IP(ipv4_tcp_bytes)
        assert p[IP].src == str(self.client_ipv4)
        assert p[IP].dst == str(self.server_ipv4)
        assert p[TCP].flags.S == True
        assert p[TCP].flags.A == False
        assert p[TCP].dport == 179
        assert p[TCP].sport == 0xFF12
        assert p[TCP].ack == 0
        assert p[TCP].dataofs == 14

        context_bytes = scapy_tcpao_context_vector_send_syn(p)
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex() == traffic_key.hex()

        message_bytes = bytes.fromhex("00 00 00 00")
        message_bytes += self.client_ipv4.packed
        message_bytes += self.server_ipv4.packed
        message_bytes += bytes.fromhex("00 06 00 38")
        message_bytes += ipv4_tcp_bytes[0x14:0x24]
        message_bytes += bytes.fromhex("00 00")
        message_bytes += ipv4_tcp_bytes[0x26:0x28]

        # Even when excluding options the TCP-AO option itself is included with zeroed MAC
        message_bytes += ipv4_tcp_bytes[0x3C:0x40]
        message_bytes += b"\x00" * 12

        assert (
            message_bytes.hex() == scapy_tcpao_message(p, include_options=False).hex()
        )

        logger.info("message: %s", message_bytes.hex(" "))
        assert mac_sha1(traffic_key, message_bytes).hex() == mac.hex()
