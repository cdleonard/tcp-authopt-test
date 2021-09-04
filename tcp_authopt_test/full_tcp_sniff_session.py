# SPDX-License-Identifier: GPL-2.0
import threading
import scapy.sessions
from scapy.packet import Packet
from scapy.layers.inet import TCP
import typing
import logging

logger = logging.getLogger(__name__)


class FullTCPSniffSession(scapy.sessions.DefaultSession):
    """Implementation of a scapy sniff session that can wait for a full TCP capture

    Allows another thread to wait for a complete FIN handshake without polling or sleep.
    """

    #: Initial Sequence Number for client
    client_isn: typing.Optional[int] = None
    #: Initial Sequence Number for server
    server_isn: typing.Optional[int] = None
    found_syn = False
    found_synack = False
    found_fin = False
    # fin sent by client
    found_client_fin = False
    # fin sent by server
    found_server_fin = False
    # fin sent by server acked by client
    found_server_finack = False
    # fin sent by server acked by client
    found_client_finack = False

    def __init__(self, server_port, **kw):
        super().__init__(**kw)
        self.server_port = server_port
        self._close_event = threading.Event()

    def on_packet_received(self, p: Packet):
        super().on_packet_received(p)
        if not p or not TCP in p:
            return
        th = p[TCP]
        # logger.debug("sport=%d dport=%d flags=%s", th.sport, th.dport, th.flags)
        if th.flags.S and not th.flags.A:
            if th.dport == self.server_port:
                self.found_syn = True
                self.client_isn = th.seq
                self.server_isn = 0
                assert th.ack == 0
        if th.flags.S and th.flags.A:
            if th.sport == self.server_port:
                self.found_synack = True
                self.server_isn = th.seq
                assert th.ack == self.client_isn + 1
        if th.flags.F:
            if self.server_port == th.dport:
                self.found_client_fin = True
                self.found_fin = True
            elif self.server_port == th.sport:
                self.found_server_fin = True
                self.found_fin = True
        if th.flags.A:
            if self.server_port == th.dport and self.found_server_fin:
                self.found_server_finack = True
            if self.server_port == th.sport and self.found_client_fin:
                self.found_client_finack = True
        if self.found_server_finack and self.found_client_finack:
            self._close_event.set()

    def wait_close(self, timeout=10):
        self._close_event.wait(timeout=timeout)
        if not self._close_event.is_set():
            raise TimeoutError("Timed out waiting for graceful close")
