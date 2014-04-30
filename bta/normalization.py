# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

class TypeFactory(object):
    pass


class Normalizer(object):
    def normal(self, val):
        return val
    def empty(self, val):
        # pylint: disable=unused-argument
        return False
