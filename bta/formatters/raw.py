# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import StringIO
import zipfile
from bta.formatters import Formatter

@Formatter.register
class Raw(Formatter):
    _name_ = "raw"
    def __init__(self):
        self.doc = []
    def add_list(self, name, lvl, lst):
        pass
    def add_section(self, section_name, lvl):
        pass
    def add_content(self, content):
        pass
    def add_table(self, name, table):
        pass
    def add_raw(self, name, content):
        self.doc.append((name,content))

    def finalize(self, encoding=None):
        return "".join([raw for name,raw in self.doc])
