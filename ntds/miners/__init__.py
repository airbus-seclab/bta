
import sys
import argparse
import bta.backend.mongo
import bta.docstruct
from bta.docstruct import LiveRootDoc, RootDoc
from bta.formatters import Formatter
import bta.formatters.rest

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
        parser.add_argument("-B", dest="backend_type", default="mongo",
                            help="database backend (amongst: %s)" % (", ".join(bta.backend.Backend.backends.keys())))

        parser.add_argument("--live-output", dest="live_output", action="store_true",
                            help="Provides a live output")
        parser.add_argument("-t", "--output-type", dest="output_type",
                            help="output document type (amongst: %s)" % (", ".join(Formatter._formatters_.keys())))
        

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
        
        if options.connection is None:
            parser.error("Missing connection string (-C)")
    
        backend_type = bta.backend.Backend.get_backend(options.backend_type)
        options.backend = backend_type(options)
        
        miner = cls.get(options.miner_name)
        m = miner()

        if not options.output_type:
            options.live_output = True

        docC = LiveRootDoc if options.live_output else RootDoc

        doc = docC("Analysis by miner [%s]" % options.miner_name)
        doc.start_stream()

        m.run(options, doc)

        doc.finish_stream()

        if options.output_type:
            fmt = Formatter.get(options.output_type)()
            doc.format_doc(fmt)
            print fmt.finalize()

    
