# SPDX-License-Identifier: GPL-2.0
import logging
import os
from contextlib import ExitStack

import pytest

from .linux_tcp_authopt import has_tcp_authopt, enable_sysctl_tcp_authopt

logger = logging.getLogger(__name__)

skipif_missing_tcp_authopt = pytest.mark.skipif(
    not has_tcp_authopt(), reason="Need CONFIG_TCP_AUTHOPT"
)


def get_effective_capabilities():
    for line in open("/proc/self/status", "r"):
        if line.startswith("CapEff:"):
            return int(line.split(':')[1], 16)


def has_effective_capability(bit) -> bool:
    return get_effective_capabilities() & (1 << bit) != 0


def can_capture() -> bool:
    return has_effective_capability(13)


def raise_skip_no_netns():
    if not has_effective_capability(12):
        pytest.skip("Need CAP_NET_ADMIN for network namespaces")


skipif_cant_capture = pytest.mark.skipif(
    not can_capture(), reason="run as root to capture packets"
)

_has_tcp_authopt_snmp = None

def has_tcp_authopt_snmp():
    global _has_tcp_authopt_snmp

    if _has_tcp_authopt_snmp is None:
        from .utils import nstat_json

        _has_tcp_authopt_snmp = "TcpExtTCPAuthOptFailure" in nstat_json()
    return _has_tcp_authopt_snmp


@pytest.fixture
def exit_stack():
    """Return a contextlib.ExitStack as a pytest fixture

    This reduces indentation making code more readable
    """
    with ExitStack() as exit_stack:
        yield exit_stack


def pytest_configure():
    # Silence messages regarding netns enter/exit:
    logging.getLogger("nsenter").setLevel(logging.INFO)
    if has_tcp_authopt():
        enable_sysctl_tcp_authopt()


def parametrize_product(**kw):
    """Parametrize each key to each item in the value list"""
    import itertools

    return pytest.mark.parametrize(",".join(kw.keys()), itertools.product(*kw.values()))
