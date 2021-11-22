import sys
from threading import Thread


class ExThread(Thread):
    """Thread class which catches run() exceptions and reports them on join."""

    def __init__(self, *args, raise_inner_on_join=True, **kwargs):
        self._inner_exc_info = None
        self.raise_inner_on_join = raise_inner_on_join
        super(ExThread, self).__init__(*args, **kwargs)

    def run(self):
        try:
            super(ExThread, self).run()
        except:
            self._inner_exc_info = sys.exc_info()

    def raise_inner(self):
        """Raise the inner exception if any"""
        ei = self._inner_exc_info
        if ei is not None:
            _, exc_value, exc_traceback = ei
            exc_value.__traceback__ = exc_traceback
            raise exc_value

    @property
    def inner_exception(self):
        """Inner exception value or None"""
        if self._inner_exc_info is not None:
            return self._inner_exc_info[1]

    def join(self, *args, **kwargs):
        super(ExThread, self).join(*args, **kwargs)
        if self.raise_inner_on_join:
            self.raise_inner()
