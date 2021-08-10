import json
import random
import subprocess
import threading
import typing
from dataclasses import dataclass
from contextlib import nullcontext

from nsenter import Namespace
from scapy.sendrecv import AsyncSniffer


class SimpleWaitEvent(threading.Event):
    @property
    def value(self) -> bool:
        return self.is_set()

    @value.setter
    def value(self, value: bool):
        if value:
            self.set()
        else:
            self.clear()

    def wait(self, timeout=None):
        """Like Event.wait except raise on timeout"""
        super().wait(timeout)
        if not self.is_set():
            raise TimeoutError(f"Timed out timeout={timeout!r}")


def recvall(sock, todo):
    """Receive exactly todo bytes unless EOF"""
    data = bytes()
    while True:
        chunk = sock.recv(todo)
        if not len(chunk):
            return data
        data += chunk
        todo -= len(chunk)
        if todo == 0:
            return data
        assert todo > 0


def randbytes(count) -> bytes:
    """Return a random byte array"""
    return bytes([random.randint(0, 255) for index in range(count)])


def nstat_json(command_prefix: str = ""):
    """Parse nstat output into a python dict"""
    runres = subprocess.run(
        f"{command_prefix}nstat -a --zeros --json",
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        encoding="utf-8",
    )
    return json.loads(runres.stdout)


def netns_context(ns: str = ""):
    """Create context manager for a certain optional netns

    If the ns argument is empty then just return a `nullcontext`
    """
    if ns:
        return Namespace("/var/run/netns/" + ns, "net")
    else:
        return nullcontext()


@dataclass
class tcphdr_authopt:
    """Representation of a TCP auth option as it appears in a TCP packet"""

    keyid: int
    rnextkeyid: int
    mac: bytes

    @classmethod
    def unpack(cls, buf) -> "tcphdr_authopt":
        return cls(buf[0], buf[1], buf[2:])

    def __repr__(self):
        return f"tcphdr_authopt({self.keyid}, {self.rnextkeyid}, bytes.fromhex({self.mac.hex(' ')!r})"


def scapy_tcp_get_authopt_val(tcp) -> typing.Optional[tcphdr_authopt]:
    for optnum, optval in tcp.options:
        if optnum == 29:
            return tcphdr_authopt.unpack(optval)
    return None


def scapy_sniffer_start_block(sniffer: AsyncSniffer, timeout=1):
    """Like AsyncSniffer.start except block until sniffing starts

    This ensures no lost packets and no delays
    """
    if sniffer.kwargs.get("started_callback"):
        raise ValueError("sniffer must not already have a started_callback")

    e = SimpleWaitEvent()
    sniffer.kwargs["started_callback"] = e.set
    sniffer.start()
    e.wait(timeout=timeout)


def scapy_sniffer_stop(sniffer: AsyncSniffer):
    """Like AsyncSniffer.stop except no error is raising if not running"""
    if sniffer is not None and sniffer.running:
        sniffer.stop()


class AsyncSnifferContext(AsyncSniffer):
    def __enter__(self):
        scapy_sniffer_start_block(self)
        return self

    def __exit__(self, *a):
        scapy_sniffer_stop(self)
