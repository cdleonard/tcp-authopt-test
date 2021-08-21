import pytest
from contextlib import ExitStack


@pytest.fixture
def exit_stack():
    """Return a contextlib.ExitStack as a pytest fixture

    This reduces indentation making code more readable
    """
    with ExitStack() as exit_stack:
        yield exit_stack
