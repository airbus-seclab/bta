# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

class Flags(object):
    _flags_ = {}
    def __init__(self, flags):
        self.flags = flags

    def test_flag(self, f):
        return bool(self.flags & f == f)

    def __getattr__(self, attr):
        if attr in self._flags_:
            return self.test_flag(self._flags_[attr])
        raise AttributeError(attr)

    def to_json(self):
        j = {}
        for k,v in self._flags_.iteritems():
            j[k] = self.test_flag(v)
        return j


class Enums(object):
    def __init__(self, val):
        renum = {}
        for k,v in self._enum_.iteritems():
            renum[v] = k
        self.renum = renum
        self.val = val
        self.text = self.renum.get(val, "unk:%r" % val)
    def to_json(self):
        return self.text
