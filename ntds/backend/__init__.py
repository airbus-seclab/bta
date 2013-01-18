#

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

    def __init__(self, options):
        self.columns = options.columns[:]

    def commit(self):
        pass
        
    def create_table(self):
        pass

    def open_table(self):
        pass

    def add_col(self, coldef):
        self.columns.append(coldef)


