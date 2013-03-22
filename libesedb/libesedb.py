#! /usr/bin/env python

from ctypes import cdll, c_void_p, c_int, pointer, byref, create_string_buffer, string_at
from esetypes import ColumnType,ValueFlags,native_type

class ESEDB_Exception(Exception):
    pass

class LibESEDB(object):
    def __init__(self):
        self.lib = cdll.LoadLibrary("libesedb.so")

    def _func(self, funcname):
        funcname = "libesedb_"+funcname
        func = getattr(self.lib, funcname)
        def _call(*args):
            e = c_void_p()
            args += (byref(e),)
            if func(*args) != 1:
                raise ESEDB_Exception("%s:??? [%r] [%i]" % (funcname, e, e.value))
        return _call

    def open(self, fname, flags=1):
        f = c_void_p()
        self._func("file_initialize")(byref(f))
        self._func("file_open")(f, fname, flags)
        return f
    def file_get_number_of_tables(self, f):
        nb = c_int()
        self._func("file_get_number_of_tables")(f, byref(nb))
        return nb.value
    def file_get_table(self, f, table_num):
        table = c_void_p()
        self._func("file_get_table")(f, table_num, byref(table))
        return table
    def table_get_utf8_name(self, table):
        sz = c_int()
        self._func("table_get_utf8_name_size")(table, byref(sz))
        name = create_string_buffer(sz.value)
        self._func("table_get_utf8_name")(table, byref(name), sz)
        return name.value.decode("utf8")
    def table_get_number_of_columns(self, table, flags=0):
        nb = c_int()
        self._func("table_get_number_of_columns")(table, byref(nb), flags)
        return nb.value
    def table_get_column(self, table, col_num, flags=0):
        column = c_void_p()
        self._func("table_get_column")(table, col_num, byref(column), flags)
        return column
    def table_free(self, table):
        self._func("table_free")(byref(table))
    def table_get_number_of_records(self, table):
        nb = c_int()
        self._func("table_get_number_of_records")(table, byref(nb))
        return nb.value
    def table_get_record(self, table, record_num):
        record = c_void_p()
        self._func("table_get_record")(table, record_num, byref(record))
        return record
    def column_get_utf8_name(self, column):
        sz = c_int()
        self._func("column_get_utf8_name_size")(column, byref(sz))
        name = create_string_buffer(sz.value)
        self._func("column_get_utf8_name")(column, byref(name), sz)
        return name.value.decode("utf8")
    def column_free(self, column):
        self._func("column_free")(byref(column))
    def record_get_number_of_values(self, record):
        sz = c_int()
        self._func("record_get_number_of_values")(record, byref(sz))
        return sz.value
    def record_get_column_identifier(self, record, value_num):
        ident = c_int()
        self._func("record_get_column_identifier")(record, value_num, byref(ident))
        return ident.value
    def record_get_column_type(self, record, value_num):
        typ = c_int()
        self._func("record_get_column_type")(record, value_num, byref(typ))
        return typ.value
    def record_get_value(self, record, value_num):
        flags = c_int()
        datalen = c_int()
        data=c_void_p()
        self._func("record_get_value")(record, value_num, byref(data), byref(datalen), byref(flags))
        return string_at(data, datalen.value), flags.value
    def record_get_long_value(self, record, value_num):
        long_value = c_void_p()
        self._func("record_get_long_value")(record, value_num, byref(long_value))
        return long_value
    def record_free(self, record):
        self._func("record_free")(byref(record))
    def long_value_get_number_of_segments(self, long_value):
        sz = c_int()
        self._func("long_value_get_number_of_segments")(long_value, byref(sz))
        return sz.value
    def long_value_get_segment_data(self, long_value, segment_num):
        datalen = c_int()
        data=c_void_p()
        self._func("long_value_get_segment_data")(long_value, segment_num, byref(data), byref(datalen))
        return string_at(data, datalen.value)


class ESEDB(object):
    def __init__(self, fname):
        self.lib = LibESEDB()
        self.file = self.lib.open(fname)
        self.tables = [ESETable(self, self.lib.file_get_table(self.file, i)) for i in range(self.lib.file_get_number_of_tables(self.file))]
        self.name2table = {t.name:t for t in self.tables}
    def __getitem__(self, i):
        try:
            return self.tables[i]
        except TypeError:
            return self.name2table[i]
    def __getattr__(self, attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError(attr)
    def __iter__(self):
        return iter(self.tables)
    def __repr__(self):
        return "<ESEDB: %s>" % " ".join(t.name for t in self.tables)

class ESETable(object):
    def __init__(self, db, table):
        self.db = db
        self.lib = db.lib
        self.table = table
        self.name = self.lib.table_get_utf8_name(table)
        self.columns = [ESEColumn(self, self.lib.table_get_column(self.table, i)) for i in range(self.lib.table_get_number_of_columns(self.table))]
        self.name2column = {c.name:c for c in self.columns}
        self.number_of_records = self.lib.table_get_number_of_records(self.table)
    def __del__(self):
        self.lib.table_free(self.table)
    def __getitem__(self, i):
        try:
            return self.columns[i]
        except TypeError:
            return self.name2column[i]
    def __getattr__(self, attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError(attr)
    def __iter__(self):
        return iter(self.columns)
    def iter_records(self):
        return (ESERecord(self, self.lib.table_get_record(self.table, i)) for i in xrange(self.number_of_records))

class ESEColumn(object):
    def __init__(self, table, column):
        self.table = table
        self.lib = table.lib
        self.column = column
        self.name = self.lib.column_get_utf8_name(self.column)
    def __del__(self):
        self.lib.column_free(self.column)

class ESERecord(object):
    def __init__(self, table, record):
        self.table = table
        self.lib = table.lib
        self.record = record
        self.values = [ESEValue(self, i) for i in range(self.lib.record_get_number_of_values(self.record))]
    def __del__(self):
        self.lib.record_free(self.record)
    def __iter__(self):
        return iter(self.values)


class ESEValue(object):
    def __init__(self, record, value_num):
        self.record = record
        self.lib = record.lib
        self.num = value_num
        self.type = self.lib.record_get_column_type(self.record.record, value_num)
        value,self.flag = self.lib.record_get_value(self.record.record, value_num)

        if self.flag & ValueFlags.LONG_VALUE:
            lv = self.lib.record_get_long_value(self.record.record, value_num)
            segnb = self.lib.long_value_get_number_of_segments(lv)
            segs = [self.lib.long_value_get_segment_data(lv, i) for i in xrange(segnb)]
            value = "".join(segs)

        self.value = native_type(self.type, value)
    

# Removed for perf reasons and because nobody needs these values yet
#
#        self.id =self.lib.record_get_column_identifier(self.record.record, value_num)
#        self.hexvalue = self.value.encode("hex")
#        self.texttype = ColumnType[self.type]
#        self.textflag = ValueFlags.flag(self.flag)
    @property
    def strvalue(self):
        if self.type in [ColumnType.BINARY_DATA, 
                         ColumnType.LARGE_BINARY_DATA, 
                         ColumnType.SUPER_LARGE_VALUE]:
            return self.value.encode("hex")
        return str(self.value)


    def __repr__(self):
        return "<val:id={0.id}:type={0.texttype}:flag={0.textflag}:value={0.hexvalue}>".format(self)


def test():
    import sys
    l = LibESEDB()
    f = l.open(sys.argv[1])
    nbt = l.file_get_number_of_tables(f)
    for i in range(nbt):
        table = l.file_get_table(f, i)
        print "%2i %s  #records=%i" % (i,l.table_get_utf8_name(table), l.table_get_number_of_records(table))
        for j in range(l.table_get_number_of_columns(table)):
            col = l.table_get_column(table, j)
            print "  %5i:%s" % (j, l.column_get_utf8_name(col))
            l.column_free(col)
        l.table_free(table)

def test2():
    import sys
    db = ESEDB(sys.argv[1])
    for r in db.sd_table.iter_records():
        print
        for v in r:
            print v


if __name__ == "__main__":
    test2()
