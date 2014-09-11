# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import argparse
import pkgutil
import sys
import bta.docstruct
from bta.docstruct import LiveRootDoc, RootDoc
import bta.backend
import bta.formatters
import bta.miners
from bta.tools.registry import Registry
import logging

log = logging.getLogger("bta.miner")




class MinerRegistry(Registry):
    pass


class Miner(object):
    _name_ = "N/A"
    _desc_ = "N/A"
    _uses_ = [ ]

    @staticmethod
    def register(f):
        return MinerRegistry.register_ref(f, key="_name_")


    @classmethod
    def create_arg_subparser(cls, parser):
        pass

    @classmethod
    def main(cls):

        logging.basicConfig(level=logging.INFO,
                            format="%(levelname)-5s: %(message)s")

        bta.backend.import_all()
        bta.formatters.import_all()
        bta.miners.import_all()


        parser = argparse.ArgumentParser(add_help=False)

        parser.add_argument("--verbose", "-v", action="count", default=0,
                            help="increase verbosity")

        parser.add_argument("-C", dest="connection",
                            help="DB connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
        parser.add_argument("-B", dest="backend_type", default="mongo",
                            choices=bta.backend.Backend.backends.keys(),
                            help="database backend")

        parser.add_argument("--force-consistency", dest="force_consistency", action="store_true",
                            help="Do not run consistency checks")
        parser.add_argument("--live-output", dest="live_output", action="store_true",
                            help="Provides a live output")
        parser.add_argument("-t", "--output-type", dest="output_type",
                            help="output document type",
                            choices=bta.formatters.Formatter._formatters_.keys())
        parser.add_argument("-o", "--output-file", dest="output",
                            help="output file", metavar="FILENAME")
        parser.add_argument("-e", "--encoding", dest="encoding", default="utf8",
                            help="output encoding. Default: utf8", metavar="ENCODING")
        parser.add_argument("--ignore-version-mismatch", dest="ignore_version_mismatch", action="store_true",
                            help="Ignore mismatch between stored data and this program's format versions")

        parser.add_argument("--module", "-m", action="append", default=[])

        globaloptions,_ = parser.parse_known_args()

        logging.root.setLevel(max(1,30-10*globaloptions.verbose))

        for m in globaloptions.module:
            imp = pkgutil.get_loader(m)
            if not imp:
                parser.error("Could not find module [%s]" % m)
            mod = imp.load_module(m)
            if hasattr(mod, "import_all"):
                mod.import_all()


        modparser = argparse.ArgumentParser(parents=[parser])

        subparsers = modparser.add_subparsers(dest='miner_name', help="Miners")
        for miner in MinerRegistry.itervalues():
            p = subparsers.add_parser(miner._name_, help=miner._desc_)
            miner.create_arg_subparser(p)

        miners = []
        remain = sys.argv[1:]
        remain.append("--")
        while remain:
            options = argparse.Namespace(miner_name=None,**vars(globaloptions))
            i = remain.index("--")
            remain,r2 = remain[:i],remain[i:]
            options,remain = modparser.parse_known_args(remain, namespace=options)
            remain = remain+r2 if remain else r2[1:]
            if options.miner_name:
                miners.append([options.miner_name, options])


        if globaloptions.connection is None:
            parser.error("Missing connection string (-C)")

        backend_type = bta.backend.Backend.get_backend(options.backend_type)
        options.backend = backend_type(options)

        if not options.output_type:
            options.live_output = True

        docC = LiveRootDoc if options.live_output else RootDoc

        multiminers = len(miners) > 1

        doc = docC("Analysis by miner%s: [%s]" % ("s" if multiminers else "",", ".join(mn for mn,o in miners)))
        doc.start_stream()

        for miner_name,opt in miners:
            miner = MinerRegistry.get(miner_name)
            m = miner(options.backend)
            if options.force_consistency:
                log.warning("Consistency checks disabled by user")
            else:
                try:
                    m.assert_consistency()
                except AssertionError, e:
                    log.error("Consistency check failed: %s" %e)
                    raise SystemExit()

            if multiminers:
                sec = doc.create_subsection("Analysis by miner [%s]" % miner_name)
                m.run(opt, sec)
                sec.finished()
            else:
                m.run(opt, doc)
        doc.finish_stream()

        if options.output_type:
            fmt = bta.formatters.Formatter.get(options.output_type)()
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
        self.raw_tables = []
        self.virtual_tables = []
        self.special_tables = []
        for tblname in self._uses_:
            t = None
            if tblname.startswith("raw."):
                n = tblname[4:]
                t = backend.open_raw_table(n)
                self.raw_tables.append(t)
            elif tblname.startswith("virtual."):
                n = tblname[8:]
                t = backend.open_virtual_table(n)
                self.virtual_tables.append(t)
            elif tblname.startswith("special."):
                n = tblname[8:]
                t = backend.open_special_table("categories")
                self.special_tables.append(t)
            if t is None:
                raise ValueError("Table name [%s] in miner [%s] (attribute %s._uses_) is unknown" %
                                 (tblname, self._name_, self.__class__.__name__))
            setattr(self, n, t)
                
    def run(self, options, doc):
        raise NotImplementedError("run")

    def assert_consistency(self):
        for table in self.raw_tables+self.virtual_tables+self.special_tables:
            table.assert_consistency()

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



class MinerGroup(Miner):
    # pylint: disable=abstract-method
    pass


class MinerList(MinerGroup):
    _report_ = None
    def run(self, options, doc):
        for m in self._report_:

            if type(m) is tuple:
                m,mopt = m[0],m[1:]
            else:
                mopt = ()

            log.info("Running miner [%s] with opt=%r" % (m,mopt))
            mdoc = doc.create_subsection("Analysis by miner [%s]" % m)

            miner = bta.miner.MinerRegistry.get(m)

            miner_parser = argparse.ArgumentParser()
            miner.create_arg_subparser(miner_parser)
            namespace = argparse.Namespace(**vars(options))
            opt = miner_parser.parse_args(mopt, namespace=namespace)

            m = miner(options.backend)

            if options.force_consistency:
                log.warning("Consistency checks disabled by user")
            else:
                try:
                    m.assert_consistency()
                except AssertionError,e:
                    log.error("Consistency check failed: %s" %e)
                    raise SystemExit()


            m.run(opt, mdoc)

            mdoc.flush()

