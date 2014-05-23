# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.tools.importer import importer_for

import_all = importer_for(__file__)

class Formatter(object):
    _formatters_ = {}
    @classmethod
    def register(cls, formatter):
        cls._formatters_[formatter._name_] = formatter
        return formatter
    @classmethod
    def get(cls, name):
        return cls._formatters_[name]

    def add_content(self, content):
        raise NotImplementedError
    def add_table(self, name, table):
        raise NotImplementedError
    def add_list(self, name, lvl, lst):
        raise NotImplementedError
    def add_section(self, seciton, lvl):
        raise NotImplementedError
    def finalize(self, encoding=None):
        raise NotImplementedError



