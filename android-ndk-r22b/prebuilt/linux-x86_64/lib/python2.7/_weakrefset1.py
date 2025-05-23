# Access WeakSet through the weakref module.
# This code is separated-out because it is needed
# by abc.py to load everything else at startup.

from _weakref import ref

__all__ = ['WeakSet']


class _IterationGuard(object):
    # This context manager registers itself in the current iterators of the
    # weak container, such as to delay all removals until the context manager
    # exits.
    # This technique should be relatively thread-safe (since sets are).

    def __init__(self, weakcontainer):
        # Don't create cycles
        self.weakcontainer = ref(weakcontainer)

    def __enter__(self):
        w = self.weakcontainer()
        if w is not None:
            w._iterating.add(self)
        return self

    def __exit__(self, e, t, b):
        w = self.weakcontainer()
        if w is not None:
            s = w._iterating
            s.remove(self)
            if not s:
                w._commit_removals()


class WeakSet(object):
    def __init__(self, data=None):
        self.data = set()
        def _remove(item, selfref=ref(self)):
            self = selfref()
            if self is not None:
                if self._iterating:
                    self._pending_removals.append(item)
                else:
                    self.data.discard(item)
        self._remove = _remove
        # A list of keys to be removed
        self._pending_removals = []
        self._iterating = set()
        if data is not None:
            self.update(data)

    def _commit_removals(self):
        l = self._pending_removals
        discard = self.data.discard
        while l:
            discard(l.pop())

    def __iter__(self):
        with _IterationGuard(self):
            for itemref in self.data:
                item = itemref()
                if item is not None:
                    yield item

    def __len__(self):
        return len(self.data) - len(self._pending_removals)

    def __contains__(self, item):
        try:
            wr = ref(item)
        except TypeError:
            return False
        return wr in self.data

    def __reduce__(self):
        return (self.__class__, (list(self),),
                getattr(self, '__dict__', None))

    __hash__ = None

    def add(self, item):
        if self._pending_removals:
            self._commit_removals()
        self.data.add(ref(item, self._remove))

    def clear(self):
        if self._pending_removals:
            self._commit_removals()
        self.data.clear()
