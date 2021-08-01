#! /usr/bin/env python

"""Check TCP Authentication Option signatures inside a packet capture"""
import logging
from dataclasses import dataclass
from scapy.packet import Packet
from scapy.utils import rdpcap
from scapy.layers.inet import TCP
from scapy.layers.inet import IP
from . import tcp_authopt_alg
from .tcp_authopt_alg import TCPAuthContext
from .tcp_authopt_alg import get_scapy_ipvx_src
from .tcp_authopt_alg import get_scapy_ipvx_dst
from .utils import scapy_tcp_get_authopt_val

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
    parser.add_argument(
        "-a",
        "--algorithm",
        dest="alg_name",
        help="Algorithm name",
        default="HMAC-SHA-1-96",
        choices=["HMAC-SHA-1-96", "AES-128-CMAC-96"],
    )
    return parser


def is_init_syn(p: Packet) -> bool:
    return p[TCP].flags.S and not p[TCP].flags.A


def main(argv=None):
    opts = create_parser().parse_args(argv)
    master_key = opts.master_key.encode()
    alg = tcp_authopt_alg.get_alg(opts.alg_name)

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
        authopt = scapy_tcp_get_authopt_val(p[TCP])
        captured_mac = authopt.mac

        saddr = get_scapy_ipvx_src(p)
        daddr = get_scapy_ipvx_dst(p)

        conn_key = p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport
        if p[TCP].flags.S:
            conn = conn_dict.get(conn_key, None)
            if conn is not None:
                logger.warning("overwrite %r", conn)
            conn = TCPAuthContext()
            conn.saddr = saddr
            conn.daddr = daddr
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

        context_bytes = conn.pack(syn=is_init_syn(p))
        traffic_key = alg.kdf(master_key, context_bytes)
        message_bytes = tcp_authopt_alg.build_message_from_scapy(
            p, include_options=False
        )
        computed_mac = alg.mac(traffic_key, message_bytes)
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
