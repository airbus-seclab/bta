#! /usr/bin/env python

# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity


import bta.backend

DEFAULT_IGNORE_LIST = {'whenChanged', 'replPropertyMetaData', 'dSCorePropagationData',
                       'nTSecurityDescriptor', 'dnsRecord', 'uSNChanged', 'Ancestors_col',
                       'recycle_time_col', 'cnt_col', 'time_col', 'PDNT_col', 'dNSTombstoned',
                       }

class TableDiff(object):
    def __init__(self, options, table, indexcol):
        self.options = options
        self.tablename = table
        self.indexcol = indexcol
        self.tableA = options.backendA.open_table(table)
        self.tableB = options.backendB.open_table(table)

    def run(self):
        cA = self.tableA.find().sort(self.indexcol)
        cB = self.tableB.find().sort(self.indexcol)

        print "==============="
        print "Starting diffing %s" % self.tablename
        print "---------------"
        icA = icB = None

        total = old = new = diff = _readA = _readB = 0

        while True:
            total += 1
            if icA is None:
                try:
                    rA = cA.next()
                except StopIteration:
                    pass
                else:
                    _readA += 1
                    icA = rA[self.indexcol]
            if icB is None:
                try:
                    rB = cB.next()
                except StopIteration:
                    pass
                else:
                    _readB += 1
                    icB = rB[self.indexcol]

            if (icA is None) and (icB is None):
                break

            if icB is None or icA is not None and icA < icB:
                print (u"A, %i: [%s]" % (icA, rA.get("name", u""))).encode('utf-8')
                icA = None
                old += 1
            elif icA is None or icA > icB:
                print (u"B, %i: [%s]" % (icB, rB.get("name", u""))).encode('utf-8')
                icB = None
                new += 1
            else:
                sA = set(rA)-{"_id"}-self.options.ignore_list
                sB = set(rB)-{"_id"}-self.options.ignore_list
                AnotB = sA-sB
                BnotA = sB-sA
                ABdiff = [k for k in sA&sB if rA[k] != rB[k]]
                nameA, nameB = rA.get("name", u""), rB.get("name", u"")
                name = nameA if nameA == nameB else "A:[%s]/B:[%s]" % (nameA, nameB)
                if AnotB or BnotA or ABdiff:
                    descr = [u"-%s" % k for k in AnotB]+[u"+%s" % k for k in BnotA]+[u"*%s[%r=>%r]" % (k, repr(rA[k])[:20], repr(rB[k])[:20]) for k in ABdiff]
                    print (u"AB, %i: [%s] %s" % (icA, name, u", ".join(descr))).encode('utf-8')
                    diff += 1
                icA = icB = None

        print "---------------"
        print "Table [%s]: %i records checked, %i disappeared, %i appeared, %i changed" % (self.tablename, total, old, new, diff)
        print "==============="




def main():
    import argparse

    bta.backend.import_all()

    parser = argparse.ArgumentParser()
    
    parser.add_argument("--CA", dest="connectionA",
                        help="Backend A connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    parser.add_argument("--CB", dest="connectionB",
                        help="Backend B connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    
    parser.add_argument("--BA", dest="backend_classA", default="mongo",
                        help="database A backend", choices=bta.backend.Backend.backends.keys())
    parser.add_argument("--BB", dest="backend_classB", default="mongo",
                        help="database B backend", choices=bta.backend.Backend.backends.keys())

    parser.add_argument("--only", dest="only", default="",
                        help="Diff only TABLENAME", metavar="TABLENAME")
    
    parser.add_argument("-X", "--ignore-field", dest="ignore_list", action="append", default=[],
                        help="Add a field name to be ignored", metavar="FIELD")
    parser.add_argument("-A", "--consider-field", dest="consider_list", action="append", default=[],
                        help="Add a field name to be considered even if present in default ignore list", metavar="FIELD")
    parser.add_argument("--ignore-version-mismatch", dest="ignore_version_mismatch", action="store_true",
                        help="Ignore mismatch between stored data and this program's format versions")
    parser.add_argument("--ignore-defaults", dest="ignore_defaults", action="store_true",
                        help="Add %s to list of ignored fields" % ", ".join(DEFAULT_IGNORE_LIST))


    options = parser.parse_args()

    if options.connectionA is None:
        parser.error("Missing connection string A (--CA)")
    if options.connectionA is None:
        parser.error("Missing connection string B (--CB)")

    options.ignore_list = set(options.ignore_list)
    options.consider_list = set(options.consider_list)
    if options.ignore_defaults:
        options.ignore_list |= DEFAULT_IGNORE_LIST
        options.ignore_list -= options.consider_list

    backend_classA = bta.backend.Backend.get_backend(options.backend_classA)
    options.backendA = backend_classA(options, options.connectionA)

    backend_classB = bta.backend.Backend.get_backend(options.backend_classB)
    options.backendB = backend_classB(options, options.connectionB)

    for tablename, otherval, indexcol in [("sd_table", ["sdtable", "sd_table", "sd"], "sd_id"),
                                         ("datatable", ["datatable", "data"], "DNT_col"),
                                         ]:
        if not options.only or options.only.lower() in otherval:
            differ = TableDiff(options, tablename, indexcol)
            differ.run()

if __name__ == "__main__":
    main()

