import logging
import typing
from contextlib import contextmanager
from pathlib import Path

from .utils import netns_context

logger = logging.getLogger(__name__)


def has_proc_tcp_authopt() -> bool:
    return Path("/proc/net/tcp_authopt").exists()


def read_proc_tcp_authopt_keys_as_lines(
    netns_name: str = "",
) -> typing.Sequence[str]:
    with netns_context(netns_name):
        return Path("/proc/net/tcp_authopt").read_text().splitlines()[1:]


@contextmanager
def verify_global_key_leak(netns: str = "") -> typing.Iterable[None]:
    """Context manager which checks that keys are not leaked after a test"""
    if not has_proc_tcp_authopt():
        yield
        return

    try:
        init_count = len(read_proc_tcp_authopt_keys_as_lines(netns))
        if init_count:
            logger.warning(
                "Already have keys in /proc/net/tcp_authopt in global namespace"
            )
        yield
    finally:
        exit_count = len(read_proc_tcp_authopt_keys_as_lines(netns))
        # logger.debug("init %d exit %d", init_count, exit_count)
        if init_count != exit_count:
            raise ValueError("Leaked keys in /proc/net/tcp_authopt")
