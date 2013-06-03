# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works


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

    def __init__(self, options, connection=None):
        self.options = options
        self.connection = connection if connection is not None else options.connection

    def commit(self):
        pass
        
    def create_table(self):
        pass

    def open_table(self):
        pass

    def add_col(self, coldef):
        self.columns.append(coldef)



class BackendTable(object):
    def __init__(self, options, db, name):
        self.options = options
        self.db = db
        self.name = name

    def insert(self, values):
        raise NotImplementedError("Table.insert()")
    def count(self):
        raise NotImplementedError("Table.count()")
