# SPDX-License-Identifier: GPL-2.0
import logging
import typing
from contextlib import ExitStack, nullcontext
from typing import ContextManager

import pytest

from .linux_tcp_authopt import enable_sysctl_tcp_authopt, has_tcp_authopt

logger = logging.getLogger(__name__)

skipif_missing_tcp_authopt = pytest.mark.skipif(
    not has_tcp_authopt(), reason="Need CONFIG_TCP_AUTHOPT"
)


def get_effective_capabilities() -> typing.Optional[int]:
    """Read CapEff from /proc/self/status

    Returns None if file is missing, for example non-linux systems.
    """
    try:
        for line in open("/proc/self/status", "r"):
            if line.startswith("CapEff:"):
                return int(line.split(":")[1], 16)
        raise Exception("Missing CapEff: line in /proc/self/status")
    except FileNotFoundError:
        return None


def has_effective_capability(bit) -> bool:
    return (get_effective_capabilities() or 0) & (1 << bit) != 0


def can_capture() -> bool:
    return has_effective_capability(13)


def raise_skip_no_netns():
    if not has_effective_capability(12):
        pytest.skip("Need CAP_NET_ADMIN for network namespaces")


skipif_cant_capture = pytest.mark.skipif(
    not can_capture(), reason="run as root to capture packets"
)


@pytest.fixture
def exit_stack():
    """Return a contextlib.ExitStack as a pytest fixture

    This reduces indentation making code more readable
    """
    with ExitStack() as exit_stack:
        yield exit_stack


def _pytest_chmod_junit_xml():
    # The vscode python plugin creates a junitxml file in /tmp and passes it to
    # pytest via --override-init. Because we run pytest as root and /tmp has the
    # sticky bit the junitxml plugin will fail to write to this file.
    #
    # Work around this by doing chown and chmod
    import sys, os
    for arg in sys.argv:
        if arg.startswith("--junit-xml="):
            path = arg[12:]
            assert os.path.exists(path)
            os.chmod(path, 0o666)
            os.chown(path, 0, 0)


def pytest_configure():
    # Silence messages regarding netns enter/exit:
    logging.getLogger("nsenter").setLevel(logging.INFO)
    _pytest_chmod_junit_xml()
    if has_tcp_authopt():
        enable_sysctl_tcp_authopt()


def parametrize_product(**kw):
    """Parametrize each key to each item in the value list"""
    import itertools

    return pytest.mark.parametrize(",".join(kw.keys()), itertools.product(*kw.values()))


def raises_optional_exception(expected_exception, **kw) -> ContextManager:
    """Like pytest.raises except accept expected_exception=None"""
    if expected_exception is None:
        return nullcontext()
    else:
        return pytest.raises(expected_exception, **kw)


@pytest.fixture(autouse=True)
def verify_global_key_leak_fixture():
    from .linux_tcp_authopt_proc import verify_global_key_leak

    with verify_global_key_leak():
        yield
