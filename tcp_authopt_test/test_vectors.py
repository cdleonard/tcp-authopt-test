import logging
from ipaddress import IPv4Address, IPv6Address
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
import struct
import hmac
from .tcp_authopt_alg import *

logger = logging.getLogger(__name__)


class TestIETFVectors:
    # https://datatracker.ietf.org/doc/html/draft-touch-tcpm-ao-test-vectors-02
    master_key = b"testvector"
    client_keyid = 61
    server_keyid = 84
    client_ipv4 = IPv4Address("10.11.12.13")
    client_ipv6 = IPv6Address("FD00::1")
    server_ipv4 = IPv4Address("172.27.28.29")
    server_ipv6 = IPv6Address("FD00::2")

    client_isn_41x = 0xFBFBAB5A
    server_isn_41x = 0x11C14261
    client_isn_42x = 0xCB0EFBEE
    server_isn_42x = 0xACD5B5E1

    def check(
        self,
        packet_hex: str,
        traffic_key_hex: str,
        mac_hex: str,
        src_isn,
        dst_isn,
        include_options=True,
        sne=0,
    ):
        p = IP(bytes.fromhex(packet_hex))
        if p[TCP].flags.S and p[TCP].flags.A is False:
            assert p[TCP].seq == src_isn
            assert p[TCP].ack == 0
        if p[TCP].flags.S and p[TCP].flags.A:
            assert p[TCP].seq == src_isn
            assert p[TCP].ack == dst_isn + 1

        context_bytes = build_context_from_scapy(p, src_isn, dst_isn)
        traffic_key = kdf_sha1(self.master_key, context_bytes)
        assert traffic_key.hex(" ") == traffic_key_hex
        message_bytes = build_message_from_scapy(p, include_options=include_options, sne=sne)
        mac = mac_sha1(traffic_key, message_bytes)
        assert mac.hex(" ") == mac_hex

    def test_4_1_1(self):
        packet_hex = """
            45 e0 00 4c dd 0f 40 00 ff 06 bf 6b 0a 0b 0c 0d
            ac 1b 1c 1d e9 d7 00 b3 fb fb ab 5a 00 00 00 00
            e0 02 ff ff ca c4 00 00 02 04 05 b4 01 03 03 08
            04 02 08 0a 00 15 5a b7 00 00 00 00 1d 10 3d 54
            2e e4 37 c6 f8 ed e6 d7 c4 d6 02 e7
        """
        traffic_key = bytes.fromhex(
            "6d 63 ef 1b 02 fe 15 09 d4 b1 40 27 07 fd 7b 04 16 ab b7 4f"
        )
        mac = bytes.fromhex("2e e4 37 c6 f8 ed e6 d7 c4 d6 02 e7")

        p = IP(bytes.fromhex(packet_hex))
        assert p[IP].src == str(self.client_ipv4)
        assert p[IP].dst == str(self.server_ipv4)
        assert p[TCP].flags.S == True
        assert p[TCP].flags.A == False
        assert p[TCP].dport == 179
        assert p[TCP].sport == 0xE9D7
        assert p[TCP].ack == 0
        assert p[TCP].chksum == 0xCAC4
        assert p[TCP].dataofs == 14
        assert p[TCP].seq == self.client_isn_41x
        assert p[TCP].ack == 0

        context_bytes = build_context_from_scapy_syn(p)
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex() == traffic_key.hex()

        packet_bytes = bytes.fromhex(packet_hex)
        message_bytes = bytes.fromhex("00 00 00 00")
        message_bytes += self.client_ipv4.packed
        message_bytes += self.server_ipv4.packed
        message_bytes += bytes.fromhex("00 06 00 38")
        message_bytes += packet_bytes[0x14:0x24]
        message_bytes += bytes.fromhex("00 00")
        message_bytes += packet_bytes[0x26:0x40]
        message_bytes += b"\x00" * 12

        assert message_bytes.hex() == build_message_from_scapy(p, include_options=True).hex()

        logger.info("message: %s", message_bytes.hex(" "))
        assert mac_sha1(traffic_key, message_bytes).hex() == mac.hex()

    def test_4_1_2(self):
        packet_hex = """
            45 e0 00 4c 65 06 40 00 ff 06 37 75 ac 1b 1c 1d
            0a 0b 0c 0d 00 b3 e9 d7 11 c1 42 61 fb fb ab 5b
            e0 12 ff ff 37 76 00 00 02 04 05 b4 01 03 03 08
            04 02 08 0a 84 a5 0b eb 00 15 5a b7 1d 10 54 3d
            ee ab 0f e2 4c 30 10 81 51 16 b3 be
        """
        traffic_key = bytes.fromhex(
            """d9 e2 17 e4 83 4a 80 ca 2f 3f d8 de 2e 41 b8 e6 79 7f ea 96"""
        )
        mac = bytes.fromhex("ee ab 0f e2 4c 30 10 81 51 16 b3 be")

        p = IP(bytes.fromhex(packet_hex))
        assert p[IP].src == str(self.server_ipv4)
        assert p[IP].sport == 179
        assert p[TCP].flags.S == True
        assert p[TCP].flags.A == True
        assert p[TCP].seq == self.server_isn_41x
        assert p[TCP].ack == self.client_isn_41x + 1
        context_bytes = build_context_from_scapy_synack(p)
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex(" ") == traffic_key.hex(" ")
        message_bytes = build_message_from_scapy(p, include_options=True)
        assert mac_sha1(traffic_key, message_bytes).hex(" ") == mac.hex(" ")

    def test_4_1_3(self):
        packet_hex = """
            45 e0 00 87 36 a1 40 00 ff 06 65 9f 0a 0b 0c 0d
            ac 1b 1c 1d e9 d7 00 b3 fb fb ab 5b 11 c1 42 62
            c0 18 01 04 a1 62 00 00 01 01 08 0a 00 15 5a c1
            84 a5 0b eb 1d 10 3d 54 70 64 cf 99 8c c6 c3 15
            c2 c2 e2 bf ff ff ff ff ff ff ff ff ff ff ff ff
            ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d
            26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02
            00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40
            06 00 64 00 01 01 00
        """
        traffic_key = bytes.fromhex(
            """d2 e5 9c 65 ff c7 b1 a3 93 47 65 64 63 b7 0e dc 24 a1 3d 71"""
        )
        mac = bytes.fromhex("70 64 cf 99 8c c6 c3 15 c2 c2 e2 bf")

        p = IP(bytes.fromhex(packet_hex))
        context_bytes = build_context_from_scapy(
            p, self.client_isn_41x, self.server_isn_41x
        )
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex(" ") == traffic_key.hex(" ")
        message_bytes = build_message_from_scapy(p, include_options=True)
        assert mac_sha1(traffic_key, message_bytes).hex(" ") == mac.hex(" ")

    def test_4_1_4(self):
        packet_hex = """
            45 e0 00 87 1f a9 40 00 ff 06 7c 97 ac 1b 1c 1d
            0a 0b 0c 0d 00 b3 e9 d7 11 c1 42 62 fb fb ab 9e
            c0 18 01 00 40 0c 00 00 01 01 08 0a 84 a5 0b f5
            00 15 5a c1 1d 10 54 3d a6 3f 0e cb bb 2e 63 5c
            95 4d ea c7 ff ff ff ff ff ff ff ff ff ff ff ff
            ff ff ff ff 00 43 01 04 da c0 00 b4 ac 1b 1c 1d
            26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02
            00 02 02 42 00 02 06 41 04 00 00 da c0 02 08 40
            06 00 64 00 01 01 00
        """
        traffic_key = bytes.fromhex(
            """d9 e2 17 e4 83 4a 80 ca 2f 3f d8 de 2e 41 b8 e6 79 7f ea 96"""
        )
        mac = bytes.fromhex("a6 3f 0e cb bb 2e 63 5c 95 4d ea c7")

        p = IP(bytes.fromhex(packet_hex))
        context_bytes = build_context_from_scapy(
            p, self.server_isn_41x, self.client_isn_41x
        )
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex(" ") == traffic_key.hex(" ")
        message_bytes = build_message_from_scapy(p, include_options=True)
        assert mac_sha1(traffic_key, message_bytes).hex(" ") == mac.hex(" ")

    def test_4_2_1(self):
        packet_hex = """
            45 e0 00 4c 53 99 40 00 ff 06 48 e2 0a 0b 0c 0d
            ac 1b 1c 1d ff 12 00 b3 cb 0e fb ee 00 00 00 00
            e0 02 ff ff 54 1f 00 00 02 04 05 b4 01 03 03 08
            04 02 08 0a 00 02 4c ce 00 00 00 00 1d 10 3d 54
            80 af 3c fe b8 53 68 93 7b 8f 9e c2
        """
        traffic_key_hex = "30 ea a1 56 0c f0 be 57 da b5 c0 45 22 9f b1 0a 42 3c d7 ea"
        mac_hex = "80 af 3c fe b8 53 68 93 7b 8f 9e c2"
        traffic_key = bytes.fromhex(traffic_key_hex)
        mac = bytes.fromhex(mac_hex)

        p = IP(bytes.fromhex(packet_hex))
        assert p[IP].src == str(self.client_ipv4)
        assert p[IP].dst == str(self.server_ipv4)
        assert p[TCP].flags.S == True
        assert p[TCP].flags.A == False
        assert p[TCP].dport == 179
        assert p[TCP].sport == 0xFF12
        assert p[TCP].ack == 0
        assert p[TCP].dataofs == 14
        assert p[TCP].seq == self.client_isn_42x
        assert p[TCP].ack == 0

        context_bytes = build_context_from_scapy_syn(p)
        logger.info("context: %s", context_bytes.hex(" "))
        assert kdf_sha1(self.master_key, context_bytes).hex() == traffic_key.hex()

        packet_bytes = bytes.fromhex(packet_hex)
        message_bytes = bytes.fromhex("00 00 00 00")
        message_bytes += self.client_ipv4.packed
        message_bytes += self.server_ipv4.packed
        message_bytes += bytes.fromhex("00 06 00 38")
        message_bytes += packet_bytes[0x14:0x24]
        message_bytes += bytes.fromhex("00 00")
        message_bytes += packet_bytes[0x26:0x28]

        # Even when excluding options the TCP-AO option itself is included with zeroed MAC
        message_bytes += packet_bytes[0x3C:0x40]
        message_bytes += b"\x00" * 12

        logger.info("message: %s", message_bytes.hex(" "))
        assert (
            message_bytes.hex() == build_message_from_scapy(p, include_options=False).hex()
        )
        assert mac_sha1(traffic_key, message_bytes).hex() == mac.hex()
        self.check(
            packet_hex,
            traffic_key_hex,
            mac_hex,
            self.client_isn_42x,
            0,
            include_options=False,
        )

    def test_4_2_2(self):
        self.check(
            """
            45 e0 00 4c 32 84 40 00 ff 06 69 f7 ac 1b 1c 1d
            0a 0b 0c 0d 00 b3 ff 12 ac d5 b5 e1 cb 0e fb ef
            e0 12 ff ff 38 8e 00 00 02 04 05 b4 01 03 03 08
            04 02 08 0a 57 67 72 f3 00 02 4c ce 1d 10 54 3d
            09 30 6f 9a ce a6 3a 8c 68 cb 9a 70
            """,
            "b5 b2 89 6b b3 66 4e 81 76 b0 ed c6 e7 99 52 41 01 a8 30 7f",
            "09 30 6f 9a ce a6 3a 8c 68 cb 9a 70",
            self.server_isn_42x,
            self.client_isn_42x,
            include_options=False,
        )

    def test_4_2_3(self):
        self.check(
            """
            45 e0 00 87 a8 f5 40 00 ff 06 f3 4a 0a 0b 0c 0d
            ac 1b 1c 1d ff 12 00 b3 cb 0e fb ef ac d5 b5 e2
            c0 18 01 04 6c 45 00 00 01 01 08 0a 00 02 4c ce
            57 67 72 f3 1d 10 3d 54 71 06 08 cc 69 6c 03 a2
            71 c9 3a a5 ff ff ff ff ff ff ff ff ff ff ff ff
            ff ff ff ff 00 43 01 04 da bf 00 b4 0a 0b 0c 0d
            26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02
            00 02 02 42 00 02 06 41 04 00 00 da bf 02 08 40
            06 00 64 00 01 01 00
            """,
            "f3 db 17 93 d7 91 0e cd 80 6c 34 f1 55 ea 1f 00 34 59 53 e3",
            "71 06 08 cc 69 6c 03 a2 71 c9 3a a5",
            self.client_isn_42x,
            self.server_isn_42x,
            include_options=False,
        )

    def test_4_2_4(self):
        self.check(
            """
            45 e0 00 87 54 37 40 00 ff 06 48 09 ac 1b 1c 1d
            0a 0b 0c 0d 00 b3 ff 12 ac d5 b5 e2 cb 0e fc 32
            c0 18 01 00 46 b6 00 00 01 01 08 0a 57 67 72 f3
            00 02 4c ce 1d 10 54 3d 97 76 6e 48 ac 26 2d e9
            ae 61 b4 f9 ff ff ff ff ff ff ff ff ff ff ff ff
            ff ff ff ff 00 43 01 04 da c0 00 b4 ac 1b 1c 1d
            26 02 06 01 04 00 01 00 01 02 02 80 00 02 02 02
            00 02 02 42 00 02 06 41 04 00 00 da c0 02 08 40
            06 00 64 00 01 01 00
            """,
            "b5 b2 89 6b b3 66 4e 81 76 b0 ed c6 e7 99 52 41 01 a8 30 7f",
            "97 76 6e 48 ac 26 2d e9 ae 61 b4 f9",
            self.server_isn_42x,
            self.client_isn_42x,
            include_options=False,
        )
