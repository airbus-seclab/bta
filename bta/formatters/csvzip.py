# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity


import os
from bta.formatters import Formatter
import StringIO
import re
import csv
import zipfile

def sane(x):
    x = re.sub(" +","_", x)
    x = re.sub("[^a-zA-Z0-9_.]+","__", x)
    return x

def utf8(x):
    if hasattr(x, "encode"):
        return x.encode("utf8")
    return repr(x)

@Formatter.register
class CSVZIP(Formatter):
    _name_ = "csvzip"
    def __init__(self):
        self.output = StringIO.StringIO()
        self.zip = zipfile.ZipFile(self.output, "w")
        self.curdir=[]
        self.desc = 0

    def _append_file(self, name, val):
        fullname = os.path.join(*(self.curdir+[sane(name)]))
        self.zip.writestr(fullname, val)
    def _add_csv(self, name, table):
        s = StringIO.StringIO()
        c=csv.writer(s, dialect="excel")
        c.writerows(table)
        self._append_file(name, s.getvalue())

    def add_table(self, name, table):
        self._add_csv(name+".csv", [map(utf8,x) if x is not None else [""] for x in table])

    def add_list(self, name, lvl, lst):
        self._add_csv(name+".csv", [([""]*lvl+[x]) for lvl,x in lst])

    def add_section(self, section_name, lvl):
        self.curdir = self.curdir[:lvl]+[sane(section_name)]

    def add_content(self, content):
        self._append_file("description_%i.txt" % self.desc, str(content))
        self.desc += 1


    def finalize(self, encoding=None):
        self.zip.close()
        return self.output.getvalue()
