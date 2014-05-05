# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

import argparse
import pkgutil
import bta.backend.mongo
import bta.docstruct
from bta.docstruct import LiveRootDoc, RootDoc
from bta.formatters import Formatter
import bta.formatters.rest
import bta.formatters.csvzip
import bta.formatters.excel
from bta.tools.registry import Registry
import logging

log = logging.getLogger("bta.miner")

class categories(object):
    def __init__(self, ct):
        for entry in ct.find():
            setattr(self, entry['name'].lower().replace('-', '_'), int(entry['id']))


class MinerRegistry(Registry):
    pass


class Miner(object):
    _desc_ = "N/A"

    @staticmethod
    def register(f):
        return MinerRegistry.register_ref(f, key="_name_")

    @classmethod
    def create_arg_parser(cls):

        parser = argparse.ArgumentParser()

        parser.add_argument("-C", dest="connection",
                            help="DB connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
        parser.add_argument("-B", dest="backend_type", default="mongo",
                            help="database backend (amongst: %s)" % (", ".join(bta.backend.Backend.backends.keys())))

        parser.add_argument("--force-consistency", dest="force_consistency", action="store_true",
                            help="Do not run consistency checks")
        parser.add_argument("--live-output", dest="live_output", action="store_true",
                            help="Provides a live output")
        parser.add_argument("-t", "--output-type", dest="output_type",
                            help="output document type (amongst: %s)" % (", ".join(Formatter._formatters_.keys())))
        parser.add_argument("-o", "--output-file", dest="output",
                            help="output file", metavar="FILENAME")
        parser.add_argument("-e", "--encoding", dest="encoding", default="utf8",
                            help="output encoding. Default: utf8", metavar="ENCODING")
        parser.add_argument("--ignore-version-mismatch", dest="ignore_version_mismatch", action="store_true",
                            help="Ignore mismatch between stored data and this program's format versions")

        subparsers = parser.add_subparsers(dest='miner_name', help="Miners")
        for miner in MinerRegistry.itervalues():
            p = subparsers.add_parser(miner._name_, help=miner._desc_)
            miner.create_arg_subparser(p)

        return parser

    @classmethod
    def create_arg_subparser(cls, parser):
        pass

    @classmethod
    def main(cls):


        preparser = argparse.ArgumentParser(add_help=False)
        preparser.add_argument("--module", "-m", action="append", default=[])

        modoptions, other = preparser.parse_known_args()
        for m in modoptions.module:
            imp = pkgutil.get_loader(m)
            if not imp:
                preparser.error("Could not find module [%s]" % m)
            mod = imp.load_module(m)
            if hasattr(mod, "import_all"):
                mod.import_all()

        parser = cls.create_arg_parser()
        parser.add_argument("--module", "-m", action="append", default=[])
        options = parser.parse_args()

        if options.connection is None:
            parser.error("Missing connection string (-C)")

        logging.basicConfig(level=logging.INFO,
                            format="%(levelname)-5s: %(message)s")

        backend_type = bta.backend.Backend.get_backend(options.backend_type)
        options.backend = backend_type(options)

        if not options.output_type:
            options.live_output = True

        miner = MinerRegistry.get(options.miner_name)
        m = miner(options.backend)
        if options.force_consistency:
            log.warning("Consistency checks disabled by user")
        else:
            try:
                m.assert_consistency()
            except AssertionError, e:
                log.error("Consistency check failed: %s" %e)
                raise SystemExit()

        docC = LiveRootDoc if options.live_output else RootDoc

        doc = docC("Analysis by miner [%s]" % options.miner_name)
        doc.start_stream()

        m.run(options, doc)

        doc.finish_stream()

        if options.output_type:
            fmt = Formatter.get(options.output_type)()
            doc.format_doc(fmt)
            try:
                fin = fmt.finalize(encoding=options.encoding)
            except UnicodeEncodeError, e:
                log.error("The chosen output encoding (%s) cannot encode the generated output: %s" % (options.encoding, e))
            else:
                if options.output:
                    open(options.output, "w").write(fin)
                else:
                    print fin

    def __init__(self, backend):
        self.backend = backend
        self.metadata = backend.open_table("metadata")
        self.datatable = backend.open_table("datatable")
        self.datatable_meta = backend.open_table("datatable_meta")
        self.link_table = backend.open_table("link_table")
        self.sd_table = backend.open_table("sd_table")
        self.category = backend.open_table("category")
        self.usersid = backend.open_table("usersid")
        self.domain = backend.open_table("domains")
        self.guid = backend.open_table("guid")
        self.dnames = backend.open_table("dnames")
        self.categories = categories(self.category)

    def run(self, options, doc):
        raise NotImplementedError("run")

    def assert_consistency(self):
        assert self.datatable.count() > 0, "datatable is empty"
        assert self.datatable_meta.count() > 0, "datatable_meta is empty"
        assert self.link_table.count() > 0, "link_table is empty"
        assert self.sd_table.count() > 0, "sd_table is empty"
        assert self.category.count() > 0, "category table is empty"
        assert self.usersid.count() > 0, "usersid table is empty"
        assert self.domain.count() > 0, "domain table is empty"

    @classmethod
    def assert_field_exists(cls, table, field):
        c = table.find({field : {"$exists":True}})
        cnt = c.limit(1).count(with_limit_and_skip=True) # stop counting after the 1st hit
        assert cnt > 0, "no record with [%s] attribute in [%s]" % (field, table.name)
    @classmethod
    def assert_field_type(cls, table, field, *types):
        r = table.find_one({field : {"$exists":True}}, {field:True})
        if r is not None:
            vtype = type(r[field])
            assert vtype in types, "unexpected type for value of attribute [%s] in table [%s] (got %r, wanted %r)" % (field, table.name, vtype, types)
