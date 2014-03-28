# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.formatters import Formatter
import StringIO
from collections import defaultdict
import xlwt

@Formatter.register
class Excel(Formatter):
    _name_ = "excel"
    def __init__(self):
        self.style_topborder = xlwt.easyxf("font: name Fixed; border: top 12")
        self.style_normal = xlwt.easyxf("font: name Fixed")
        self.style_section = xlwt.easyxf("font: bold 1")
        self.book = xlwt.Workbook()
        self.reportsheet = self.book.add_sheet("Report")
        self.reportsheet.show_grid = False
        self.row = 0
        self.col = 0

    def add_table(self, name, table):
        sht = self.book.add_sheet(name)

        self.reportsheet.write(self.row, 0, xlwt.Formula('HYPERLINK("#{0}!A1", "See {1}")'.format(
            xlwt.Utils.quote_sheet_name(name),  name)))
        self.row += 1

        style = self.style_normal
        r = 0
        lengths=defaultdict(int)
        for row in table:
            if row:
                for c,val in enumerate(row):
                    sht.write(r, c, val, style)
                    lengths[c] = max(lengths[c],len(val))
                r += 1
                style = self.style_normal
            else:
                style = self.style_topborder
        for c,v in lengths.iteritems():
            sht.col(c).width = int(256*1.2*v)
    def add_list(self, name, lvl, lst):
        self.add_table(name, lst)

    def add_section(self, section_name, lvl):
        self.reportsheet.write(self.row, lvl, section_name, self.style_section)
        self.row += 1

    def add_content(self, content):
        self.reportsheet.write(self.row, 0, content)
        self.row += 1


    def finalize(self, encoding=None):
        s = StringIO.StringIO()
        self.book.save(s)
        return s.getvalue()
