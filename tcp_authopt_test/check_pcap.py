#! /usr/bin/env python

"""Check TCP Authentication Option signatures inside a packet capture"""
import sys
import logging
from scapy.packet import Packet
from scapy.utils import rdpcap

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


def main(argv=None) -> int:
    opts = create_parser().parse_args(argv)

    from .validator import TcpAuthValidator
    from .validator import TcpAuthValidatorKey
    key = TcpAuthValidatorKey(key=opts.master_key.encode(), alg_name=opts.alg_name)
    validator = TcpAuthValidator(keys=[key])
    cap = rdpcap(opts.file)
    logger.info("cap: %r", cap)
    for p in cap:
        validator.handle_packet(p)
    rc = 0
    if validator.any_fail:
        rc = 1
    elif validator.any_incomplete:
        rc = 2
    return rc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
