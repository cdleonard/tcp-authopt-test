# SPDX-License-Identifier: GPL-2.0


class FlagProperty:
    """Helper for implementing flag properties"""

    def __init__(self, maskprop: str, flag: int, rev=False):
        self.maskprop = maskprop
        self.flag = flag
        self.rev = bool(rev)

    def __get__(self, obj, objtype=None) -> bool:
        return (getattr(obj, self.maskprop) & self.flag != 0) ^ self.rev

    def __set__(self, obj, val) -> bool:
        mask = getattr(obj, self.maskprop)
        if val ^ self.rev:
            mask |= self.flag
        else:
            mask &= ~self.flag
        setattr(obj, self.maskprop, mask)
        return val
