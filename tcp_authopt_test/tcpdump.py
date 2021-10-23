"""Perform tcpdump capture as a python context manager"""
import errno
import logging
import os
import subprocess
import time
from contextlib import contextmanager

from .netns_fixture import NamespaceFixture

logger = logging.getLogger(__name__)


def subprocess_kill(popen: subprocess.Popen, kill_timeout=1, term_timeout=1):
    popen.kill()
    try:
        popen.wait(timeout=kill_timeout)
        return
    except subprocess.TimeoutExpired:
        logger.warning("wait timeout after kill, try terminate")

    popen.terminate()
    try:
        popen.wait(timeout=term_timeout)
        return
    except subprocess.TimeoutExpired:
        logger.error("wait timeout after terminate", exc_info=True)
        raise


@contextmanager
def tcpdump_capture(namespace=None, interface=None, extra_args=None, filename=None):
    import subprocess

    cmd = ["tcpdump"]
    cmd += ["--packet-buffered"]
    if filename:
        cmd += ["-w", filename]
    if namespace:
        cmd = ["ip", "netns", "exec", namespace] + cmd
    if interface:
        cmd += ["-i", interface]
    if extra_args:
        cmd += extra_args
    popen = subprocess.Popen(cmd)
    yield popen
    subprocess_kill(popen)


def symlink_force(src, dst, force=True):
    try:
        os.symlink(src, dst)
    except OSError as e:
        if force and e.errno == errno.EEXIST:
            os.unlink(dst)
            os.symlink(src, dst)
        else:
            raise


@contextmanager
def tcpdump_capture_nsfixture(nsfixture: NamespaceFixture):
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    client_capture_filename = f"client_{timestamp}.pcap"
    server_capture_filename = f"server_{timestamp}.pcap"
    with tcpdump_capture(
        namespace=nsfixture.client_netns_name,
        filename=client_capture_filename,
        interface="veth0",
    ):
        with tcpdump_capture(
            namespace=nsfixture.server_netns_name,
            filename=server_capture_filename,
            interface="veth0",
        ):
            logger.info(f"capturing {os.path.abspath(client_capture_filename)}")
            logger.info(f"capturing {os.path.abspath(server_capture_filename)}")
            symlink_force(client_capture_filename, "client_latest.pcap")
            symlink_force(server_capture_filename, "server_latest.pcap")
            yield
