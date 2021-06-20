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


def scapy_tcpao_context_vector(p: Packet) -> bytes:
    return tcpao_context_vector(
        p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport, p[TCP].seq, 0
    )


def scapy_tcpao_message(p: Packet, include_options=True) -> bytes:
    sne_bytes = struct.pack("!I", 0)
    ipv4_pseudo_header = struct.pack(
        "!4s4sHH",
        IPv4Address(p[IP].src).packed,
        IPv4Address(p[IP].dst).packed,
        6,
        p[TCP].dataofs * 4 + len(p[TCP].payload),
    )
    logger.info("ipv4 pseudo header: %s", ipv4_pseudo_header.hex(" "))
    tcp_header = bytes(p[TCP])[:16] + b"\x00\x00" + bytes(p[TCP])[18:20]
    return sne_bytes + ipv4_pseudo_header + tcp_header + bytes(p[TCP].payload)


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

        context_bytes = scapy_tcpao_context_vector(p)
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

        # assert (message_bytes == scapy_tcpao_message(p, include_options=True))

        logger.info("message: %s", message_bytes.hex(" "))
        assert mac_sha1(traffic_key, message_bytes).hex() == mac.hex()

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

        context_bytes = scapy_tcpao_context_vector(p)
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

        # assert (message_bytes == scapy_tcpao_message(p, include_options=False))

        logger.info("message: %s", message_bytes.hex(" "))
        assert mac_sha1(traffic_key, message_bytes).hex() == mac.hex()
