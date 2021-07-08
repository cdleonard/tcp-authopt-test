import os
from pathlib import Path
from .check_pcap import main


def get_capture_path(name) -> Path:
    return Path(__file__).parent.joinpath(name)


def test_cisco():
    main(["-k", "123", "-v", "-f", str(get_capture_path("cisco.pcap"))])


def test_cisco2():
    main(["-k", "123", "-v", "-f", str(get_capture_path("cisco2.pcap"))])
