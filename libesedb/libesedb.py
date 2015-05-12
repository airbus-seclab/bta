#! /usr/bin/env python

# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity


from ctypes import cdll, c_void_p, c_int, pointer, byref, create_string_buffer, string_at
from esetypes import ColumnType,ValueFlags,native_type,multi_native_type
from sys import platform

import logging
log = logging.getLogger("libesedb")

class ESEDB_Exception(Exception):
    pass

class ESEDB_Error(ESEDB_Exception):
    pass

class LibESEDB(object):
    # keep references to those functions that are called in destructors
    byref = byref
    c_void_p = c_void_p
    def __init__(self, ignore_errors=False, report_error=lambda x:None):
        self.ignore_errors = ignore_errors
        self.report_error = report_error
        try:
            if platform.startswith("linux"):
                self.lib = cdll.LoadLibrary("libesedb.so")
            elif platform.startswith("win32"):
                self.lib = cdll.LoadLibrary("libesedb.dll")
            elif platform.startswith("darwin"):
                self.lib = cdll.LoadLibrary("libesedb.dylib")
        except OSError,e:
            if e.args[0].endswith("cannot open shared object file: No such file or directory"):
                raise ESEDB_Error(
                    "%s. Did you install it or did you use LD_LIBRARY_PATH correctly ?" 
                    % e.message)
            raise
        self.error = c_void_p()
        self.error_p = pointer(self.error)

    def _func(self, funcname):
        funcname = "libesedb_"+funcname
        func = getattr(self.lib, funcname)
        def _call(*args):
            args += (self.error_p,)
            if func(*args) != 1:
                errmsg = "%s: %s" % (funcname, self.get_error(self.error))
                if self.ignore_errors:
                    errmsg = "IGNORED: %s" % errmsg
                    log.warning(errmsg)
                    self.report_error(errmsg)
                    return
                raise ESEDB_Exception(errmsg)
        return _call

    def get_error(self, error):
        sz = 2048
        msgbuf = create_string_buffer(sz)
        if self.lib.liberror_error_sprint(error, byref(msgbuf), sz) == -1:
            raise ESEDB_Exception("liberror_error_sprint: unkown error!")
        return msgbuf.value

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
        self._func("table_free")(self.byref(table))
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
    def column_get_type(self, column):
        typ = c_int()
        self._func("column_get_type")(column, byref(typ))
        return typ.value
    def column_free(self, column):
        self._func("column_free")(self.byref(column))
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
        self._func("record_free")(self.byref(record))
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
    def __init__(self, fname, ignore_errors=False, report_error=None):
        self.lib = LibESEDB(ignore_errors=ignore_errors, report_error=report_error)
        self.file = self.lib.open(fname)
        self.tables = [ESETable(self, i) for i in range(self.lib.file_get_number_of_tables(self.file))]
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
    def __init__(self, db, table_num):
        self.db = db
        self.lib = db.lib
        self.table_num = table_num
        self.table = self.lib.file_get_table(self.db.file, table_num)
        self.name = self.lib.table_get_utf8_name(self.table)
        self.columns = [ESEColumn(self, i) for i in range(self.lib.table_get_number_of_columns(self.table))]
        self.name2column = {c.name:c for c in self.columns}
        self._number_of_records = None # expensive to get, so we wait for it to be actually needed
    @property
    def number_of_records(self):
        if self._number_of_records is None:
            self._number_of_records = self.lib.table_get_number_of_records(self.table)
        return self._number_of_records
    def __del__(self):
        if hasattr(self, "table"):
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
    def iter_records(self, entries=None, columns=None):
        if entries is None:
            if columns is not None:
                entries = [c.column_num for c in columns]
        return (ESERecord(self, i, limit=entries) for i in xrange(self.number_of_records))

class ESEColumn(object):
    def __init__(self, table, column_num):
        self.table = table
        self.lib = table.lib
        self.column_num = column_num
        self.column = self.lib.table_get_column(self.table.table, column_num)
        try:
            self.name = self.lib.column_get_utf8_name(self.column)
            self.type = self.lib.column_get_type(self.column)
        finally:
            self.lib.column_free(self.column)
            self.column = None

class ESERecord(object):
    def __init__(self, table, record_num, limit=None):
        self.table = table
        self.lib = table.lib
        self.record_num = record_num
        self.record = self.lib.table_get_record(self.table.table, record_num)
        try:
            self.value_entries = limit if limit is not None else range(self.lib.record_get_number_of_values(self.record))
            self.values=list()
            for i in self.value_entries:
                try:
                    self.values.append(ESEValue(self, i))
                except:
                    a=ESEValue(self,i)
                    a.value=u"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    self.values.append(a)
                    log.warning("====> %r" % (ESEValue(self,i)))

        finally:
            self.lib.record_free(self.record)
            self.record = None

    def __iter__(self):
        return iter(self.values)


class ESEValue(object):
    __slots__ = ["record", "lib", "num", "type", "flags", "value"]
    def __init__(self, record, value_num):
        self.record = record
        self.lib = record.lib
        self.num = value_num
        self.type = self.record.table.columns[value_num].type
        value,self.flags = self.lib.record_get_value(self.record.record, value_num)
        if not value:
            self.value = None
        else:

            if self.flags & ValueFlags.LONG_VALUE:
                try:
                    lv = self.lib.record_get_long_value(self.record.record, value_num)
                except ESEDB_Exception,e:
                    log.warning("error %s on line %d column %d flag %08x" % (e,self.record.record_num,value_num, self.flags))
                    value = None
                    raise
                else:
                    segnb = self.lib.long_value_get_number_of_segments(lv)
                    segs = [self.lib.long_value_get_segment_data(lv, i) for i in xrange(segnb)]
                    value = "".join(segs)

            if self.flags & ValueFlags.MULTI_VALUE:
                self.value = multi_native_type(self.flags, self.type, value)
            else:
                self.value = native_type(self.type, value)
                
    

# Removed for perf reasons and because nobody needs these values yet
#
#        self.id =self.lib.record_get_column_identifier(self.record.record, value_num)
#        self.hexvalue = self.value.encode("hex")
#        self.texttype = ColumnType[self.type]
#        self.textflags = ValueFlags.flag(self.flags)


    @property
    def strvalue(self):
        if self.value is None:
            return ""
        if self.type in [ColumnType.BINARY_DATA, 
                         ColumnType.LARGE_BINARY_DATA, 
                         ColumnType.SUPER_LARGE_VALUE]:
            return self.value.encode("hex")
        return str(self.value)


    def __repr__(self):
        return "<val:type=%s:flags=%s:value=%s>" % (ColumnType[self.type], ValueFlags.flag(self.flags), self.strvalue )


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

def test3():
    import sys
    db = ESEDB(sys.argv[1])
    sys.stdout.write("\t".join(c.name for c in db.sd_table) + "\n")
    i = 0
    for r in db.datatable.iter_records():
        sys.stdout.write("\t".join(v.strvalue for v in r) + "\n")
        i+=1
        if i > 500:
            break


if __name__ == "__main__":
    test3()
