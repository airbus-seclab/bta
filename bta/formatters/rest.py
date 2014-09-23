# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity


import itertools
from bta.formatters import Formatter

def get_indent(lvl):
    return "  "*lvl

def get_bullet(lvl):
    b = {0:"*", 1:"+", 2:"-"}.get(lvl, "*")
    return get_indent(lvl)+b


def format_table(table,  width_hint=200):
    # pylint: disable=multiple-statements
    sep = " | " ; lsep = "| " ; rsep = " |"
    cross = "-+-" ; lcross = "+-"; rcross = "-+"
    dcross = "=+=" ; ldcross = "+="; rdcross = "=+"
    # pylint: enable=multiple-statements
    tl = map(max, zip(*[map(len,l) for l in table if l]))
    total_width = sum(tl)+len(tl)*len(sep)
    if total_width > width_hint:
        tl = [max(min(tl), l if l < width_hint/2 else int(round(float(l*width_hint)/total_width))) for l in tl]
    fmt = lsep + (sep.join(["%%-%is"]*len(tl)) % tuple(tl)) + rsep
    hfmt = lcross + ( cross.join(["%%-%is"]*len(tl)) % tuple(tl) ) + rcross
    hline = hfmt % tuple(["-"*l for l in tl])
    hhfmt = ldcross + ( dcross.join(["%%-%is"]*len(tl)) % tuple(tl) ) + rdcross
    hhline = hhfmt % tuple(["="*l for l in tl])
    return fmt, hline, hhline

def normalize_table(table):
    #ensure all lines have the same number of columns
    maxcol = max(len(l) for l in table if l)
    t2 = []
    for l in table:
        if l:
            l += ("",)*(maxcol-len(l))
        t2.append(l)
    return t2


@Formatter.register
class ReST(Formatter):
    _name_ = "ReST"
    def __init__(self):
        self.doc = []

    def add_table(self, name, table):
        table = normalize_table(table)
        t = []
        fmt,hline,hhline = format_table(table)

        skip = 0
        t.append(hline)
        if len(table) > 2 and table[0] and not table[1]:
            t.append(fmt % tuple(table[0]))
            t.append(hhline)
            skip = 2

        for l in itertools.islice(table, skip, None):
            t.append(fmt % tuple(l) if l else hline)
        t.append(hline)
        self.doc.append("\n".join(t))

    def add_list(self, name, lvl, lst):
        self.doc.append("%s %s:" % (get_bullet(lvl-1), name.encode('unicode-escape')))
        for content in lst:
            self.doc.append("%s %s" % (get_bullet(lvl), content.encode('unicode-escape')))

    def add_section(self, section_name, lvl):
        self.doc.append("")
        self.doc.append(section_name)
        if 0 <= lvl < 3:
            uline = ["=", "-", "~"][lvl]
            self.doc.append(uline*len(section_name))
            self.doc.append("")

    def add_raw(self, name, content):
        self.doc.append("\n.. raw::\n")
        safe_content = "  "+content.translate("........\x08.\x0a....................."
                                              +" !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
                                              +"."*129).replace("\n", "\n  ")+"\n"
        self.doc.append(safe_content)

    def add_content(self, content):
        self.doc.append(unicode(content))


    def finalize(self, encoding=None):
        fin = "\n".join(self.doc)
        if encoding:
            fin = fin.encode(encoding)
        return fin

