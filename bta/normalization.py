# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

class TypeFactory(object):
    pass


class Normalizer(object):
    def normal(self, val):
        return val
    def empty(self, val):
        # pylint: disable=unused-argument
        return False
