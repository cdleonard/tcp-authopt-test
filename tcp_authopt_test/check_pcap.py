#! /usr/bin/env python

"""Check TCP Authentication Option signatures inside a packet capture"""
import logging
from dataclasses import dataclass
from ipaddress import IPv4Address
from scapy.packet import Packet
from scapy.utils import rdpcap
from scapy.layers.inet import TCP
from scapy.layers.inet import IP
from . import tcp_authopt_alg

logger = logging.getLogger()


def adjust_logging(delta, logger_name=None):
    """Adjust logging on one logger."""
    logger = logging.getLogger(logger_name)
    old_level = logger.getEffectiveLevel()
    logger.setLevel(old_level + delta)


def create_parser():
    import argparse

    class IncreaseLogLevelAction(argparse.Action):
        def __call__(self, *args, **kwargs):
            adjust_logging(-10)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-v",
        "--verbose",
        nargs=0,
        help="Increase logging level.",
        action=IncreaseLogLevelAction,
        default=argparse.SUPPRESS,
    )
    parser.add_argument("-f", "--file", help="capture file")
    parser.add_argument("-k", "--master-key", help="master secret key")
    return parser


@dataclass
class TCPConnectionContext:
    saddr: IPv4Address = None
    daddr: IPv4Address = None
    sport: int = 0
    dport: int = 0
    src_isn: int = 0
    dst_isn: int = 0

    def build_tcp_authopt_traffic_context(self, is_init_syn=False):
        return tcp_authopt_alg.build_context(
            self.saddr,
            self.daddr,
            self.sport,
            self.dport,
            self.src_isn,
            self.dst_isn if not is_init_syn else 0,
        )


def is_init_syn(p: Packet) -> bool:
    return p[TCP].flags.S and not p[TCP].flags.A


def main(argv=None):
    opts = create_parser().parse_args(argv)
    master_key = opts.master_key.encode()

    def kdf_alg(master_key, context_bytes):
        return tcp_authopt_alg.kdf_sha1(master_key, context_bytes)

    def mac_alg(traffic_key, message_bytes):
        return bytes(tcp_authopt_alg.mac_sha1(traffic_key, message_bytes))

    def hexstr(arg: bytes) -> str:
        return arg.hex(" ")

    cap = rdpcap(opts.file)
    logger.info("cap: %r", cap)
    conn_dict = dict()
    for packet_index in range(len(cap)):
        p = cap[packet_index]
        if TCP not in p.layers():
            logger.debug("skip non-TCP packet")
            continue
        tcp = p[TCP]
        for optnum, optval in tcp.options:
            if optnum != 29:
                logger.debug("[%s]: TCP %r optval %r", packet_index, optnum, optval)
                continue
            logger.info("[%d]: TCP-AO %s", packet_index, hexstr(optval))
            if len(optval) < 2:
                logger.warning("TCP-AO option too short!")
                continue

            keyid = optval[0]
            rnextkeyid = optval[1]
            captured_mac = optval[2:]

            conn_key = p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport
            if p[TCP].flags.S:
                conn = conn_dict.get(conn_key, None)
                if conn is not None:
                    logger.warning("overwrite %r", conn)
                conn = TCPConnectionContext()
                conn.saddr = IPv4Address(p[IP].src)
                conn.daddr = IPv4Address(p[IP].dst)
                conn.sport = p[TCP].sport
                conn.dport = p[TCP].dport
                conn_dict[conn_key] = conn

                logger.info("conn %r", conn)
                if p[TCP].flags.A == False:
                    # SYN
                    conn.src_isn = p[TCP].seq
                    conn.dst_isn = 0
                else:
                    # SYN/ACK
                    conn.src_isn = p[TCP].seq
                    conn.dst_isn = p[TCP].ack - 1

                    # Update opposite connection with dst_isn
                    rconn_key = p[IP].dst, p[IP].src, p[TCP].dport, p[TCP].sport
                    rconn = conn_dict.get(rconn_key, None)
                    if rconn is None:
                        logger.warning("missing reverse connection %s", rconn_key)
                    else:
                        assert rconn.src_isn == conn.dst_isn
                        assert rconn.dst_isn == 0
                        rconn.dst_isn = conn.src_isn
            else:
                conn = conn_dict.get(conn_key, None)
                if conn is None:
                    logger.warning("missing TCP syn for %r", conn_key)
                    continue
            logger.debug("index %d key %r conn %r", packet_index, conn_key, conn)

            context_bytes = conn.build_tcp_authopt_traffic_context(is_init_syn(p))
            traffic_key = kdf_alg(master_key, context_bytes)
            message_bytes = tcp_authopt_alg.build_message_from_scapy(
                p, include_options=False
            )
            computed_mac = mac_alg(traffic_key, message_bytes)
            if computed_mac == captured_mac:
                logger.info("ok - packet %d mac %s", packet_index, hexstr(computed_mac))
            else:
                logger.info(
                    "not ok - packet %d captured %s computed %s",
                    packet_index,
                    captured_mac,
                    computed_mac,
                )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
