# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.tools.importer import importer_for

import_all = importer_for(__file__)


class Backend(object):
    backends={}
    @classmethod
    def register(cls, name):
        def doreg(c):
            cls.backends[name.lower()] = c
            return c
        return doreg
    @classmethod
    def get_backend(cls, name):
        return cls.backends[name.lower()]

    def __init__(self, options, connection=None, database=None):
        self.options = options
        self.db = database
        if database is None:
            self.connection = connection if connection is not None else options.connection
        else:
            self.connection = None

    def commit(self):
        pass

    def create_table(self):
        raise NotImplementedError("Backend.create_table()")
    def open_table(self, name):
        return self.open_raw_table(name)
    def open_raw_table(self, name):
        raise NotImplementedError("Backend.open_raw_table()")
    def open_virtual_table(self, name):
        raise NotImplementedError("Backend.open_virtual_table()")
    def open_special_table(self, name):
        raise NotImplementedError("Backend.open_special_table()")
    def list_tables(self):
        raise NotImplementedError("Backend.list_tables()")


class BackendTable(object):
    def assert_consistency(self):
        raise NotImplementedError("BackendTable.assert_consistency()")


class RawTable(BackendTable):
    def __init__(self, options, db, name):
        self.options = options
        self.db = db
        self.name = name

    def create(self):
        raise NotImplementedError("Table.create()")

    def create_with_fields(self, columns):
        raise NotImplementedError("Table.create_with_fields()")
    def insert_fields(self, values):
        raise NotImplementedError("Table.insert_fields()")
    def create_index(self, colname):
        raise NotImplementedError("Table.create_index()")

    def count(self):
        raise NotImplementedError("Table.count()")
    def find(self, *args, **kargs):
        raise NotImplementedError("Table.find()")
    def find_one(self, *args, **kargs):
        raise NotImplementedError("Table.find_one()")

    def insert(self, values):
        raise NotImplementedError("Table.insert()")
    def update(self, *args, **kargs):
        raise NotImplementedError("Table.update()")



class VirtualTable(BackendTable):
    def __init__(self, options, backend, name):
        self.options = options
        self.backend = backend
        self.name = name
    def count(self):
        raise NotImplementedError("VirtualTable.count()")
    def find(self, request, projection=None):
        raise NotImplementedError("VirtualTable.find()")


class SpecialTable(BackendTable):
    pass
