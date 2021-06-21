"""Packet-processing utilities implementing RFC5925 and RFC2926"""

import logging
from ipaddress import IPv4Address, IPv6Address
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
import struct
import hmac

logger = logging.getLogger(__name__)


def kdf_sha1(master_key: bytes, context: bytes) -> bytes:
    """RFC5926 section 3.1.1.1"""
    input = b"\x01" + b"TCP-AO" + context + b"\x00\xa0"
    return hmac.digest(master_key, input, "SHA1")


def mac_sha1(traffic_key: bytes, message: bytes) -> bytes:
    """RFC5926 section 3.2.1"""
    return hmac.digest(traffic_key, message, "SHA1")[:12]


def build_context(saddr, daddr, sport, dport, src_isn, dst_isn) -> bytes:
    """Build context bytes as specified by RFC5925 section 5.2"""
    return struct.pack(
        "!4s4sHHII",
        IPv4Address(saddr).packed,
        IPv4Address(daddr).packed,
        sport,
        dport,
        src_isn,
        dst_isn,
    )


def build_context_from_scapy(p: Packet, src_isn: int, dst_isn: int) -> bytes:
    """Build context based on a scapy Packet and src/dst initial-sequence numbers"""
    return build_context(
        p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport, src_isn, dst_isn
    )


def build_context_from_scapy_syn(p: Packet) -> bytes:
    """Build context for a scapy SYN packet"""
    return build_context_from_scapy(p, p[TCP].seq, 0)


def build_context_from_scapy_synack(p: Packet) -> bytes:
    """Build context for a scapy SYN/ACK packet"""
    return build_context_from_scapy(p, p[TCP].seq, p[TCP].ack - 1)


def build_message_from_scapy(p: Packet, include_options=True, sne=0) -> bytearray:
    """Build message bytes as described by RFC5925 section 5.1"""
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
