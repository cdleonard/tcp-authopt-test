import logging
import selectors
import socket
import os
from ipaddress import IPv4Address
from contextlib import ExitStack
from threading import Thread
import pytest

logger = logging.getLogger(__name__)


class SimpleServerThread(Thread):
    def __init__(self, socket, mode="recv"):
        self.listen_socket = socket
        self.mode = mode
        super().__init__()

    def read_echo(self, conn, events):
        data = conn.recv(1000)
        if len(data) == 0:
            print("closing", conn)
            self.sel.unregister(conn)
        else:
            if self.mode == "echo":
                conn.sendall(data)
            elif self.mode == "recv":
                pass
            else:
                raise ValueError(f"Unknown mode {self.mode}")

    def _stop_pipe_read(self, conn, events):
        self.should_loop = False

    def start(self) -> None:
        self.exit_stack = ExitStack()
        self._stop_pipe_rfd, self._stop_pipe_wfd = os.pipe()
        self.exit_stack.callback(lambda: os.close(self._stop_pipe_rfd))
        self.exit_stack.callback(lambda: os.close(self._stop_pipe_wfd))
        return super().start()

    def run(self):
        self.should_loop = True
        conn, _addr = self.listen_socket.accept()
        conn = self.exit_stack.enter_context(conn)
        conn.setblocking(False)
        self.sel = self.exit_stack.enter_context(selectors.DefaultSelector())
        self.sel.register(conn, selectors.EVENT_READ, self.read_echo)
        self.sel.register(self._stop_pipe_rfd, selectors.EVENT_READ, self._stop_pipe_read)
        while self.should_loop:
            for key, events in self.sel.select(timeout=1):
                callback = key.data
                callback(key.fileobj, events)

    def stop(self):
        """Try to stop nicely"""
        os.write(self._stop_pipe_wfd, b'Q')
        self.join()
        self.exit_stack.close()


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


@pytest.fixture
def exit_stack():
    with ExitStack() as exit_stack:
        yield exit_stack


def test_nonauth_connect(exit_stack):
    tcp_server_host = ''
    tcp_server_port = 50001

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket = exit_stack.push(listen_socket)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((tcp_server_host, tcp_server_port))
    listen_socket.listen(1)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)

    server_thread = SimpleServerThread(listen_socket, mode="echo")
    server_thread.start()
    exit_stack.callback(server_thread.stop)

    client_socket.connect(("localhost", tcp_server_port))

    client_socket.sendall(b"0" * 3000)
    buf = recvall(client_socket, 3000)
    assert(len(buf) == 3000)


def test_multi():
    for i in range(10):
        with ExitStack() as exit_stack:
            logger.info("ITER %d", i)
            test_nonauth_connect(exit_stack)


from .tcp_md5sig import setsockopt_md5sig, tcp_md5sig, sockaddr_in


def test_md5sig_packunpack():
    s1 = tcp_md5sig(flags=0, prefixlen=0, ifindex=0, keylen=0, key=b"a\x00b")
    s2 = tcp_md5sig.unpack(s1.pack())
    assert(s1.key[0:2] == s2.key[0:2])
    assert(len(s2.key) == 80)


def test_md5_basic(exit_stack):
    tcp_server_host = ''
    tcp_server_port = 50001
    tcp_md5_key = b"12345"

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket = exit_stack.push(listen_socket)
    setsockopt_md5sig(listen_socket,
            keylen=len(tcp_md5_key),
            key=tcp_md5_key,
            addr=sockaddr_in(port=0, addr=IPv4Address("127.0.0.1")))
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind((tcp_server_host, tcp_server_port))
    listen_socket.listen(1)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket = exit_stack.push(client_socket)
    setsockopt_md5sig(client_socket,
            keylen=len(tcp_md5_key),
            key=tcp_md5_key,
            addr=sockaddr_in(port=tcp_server_port, addr=IPv4Address("127.0.0.1")))

    server_thread = SimpleServerThread(listen_socket, mode="echo")
    server_thread.start()
    exit_stack.callback(server_thread.stop)

    client_socket.connect(("localhost", tcp_server_port))

    client_socket.sendall(b"0" * 3000)
    buf = recvall(client_socket, 3000)
    assert(len(buf) == 3000)
