
import argparse
import ntds.backend.mongo

class Miner(object):
    _miners_ = {}
    _desc_ = "N/A"
    @classmethod
    def register(cls, miner):
        cls._miners_[miner._name_] = miner
        return miner
    @classmethod
    def get(cls, minername):
        return cls._miners_[minername]

    @classmethod
    def create_arg_parser(cls):
        
        parser = argparse.ArgumentParser()#usage)

        parser.add_argument("-C", dest="connection",
                            help="DB connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
        parser.add_argument("-t", dest="tablename",
                            help="table name to create in database", metavar="TABLENAME")
        parser.add_argument("-B", dest="backend", default="mongo",
                            help="database backend (amongst: %s)" % (", ".join(ntds.backend.Backend.backends.keys())))
        

        subparsers = parser.add_subparsers(dest='miner_name', help="Miners")
        for miner in cls._miners_.itervalues():
            p = subparsers.add_parser(miner._name_, help=miner._desc_)
            miner.create_arg_subparser(p)

        return parser

    @classmethod
    def create_arg_subparser(cls, parser):
        pass

    @classmethod
    def main(cls):
        parser = cls.create_arg_parser()
        options = parser.parse_args()
        
        if options.tablename is None:
            parser.error("Missing table name (-t)")
        if options.connection is None:
            parser.error("Missing connection string (-C)")
    
        db_backend = ntds.backend.Backend.get_backend(options.backend)
        options.columns = []
        options.db = db_backend(options)
        
        miner = cls.get(options.miner_name)
        m = miner()
        m.run(options)

    
