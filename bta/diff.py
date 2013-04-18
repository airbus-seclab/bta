#! /usr/bin/env python

import bta.backend.mongo


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
        
        total = old = new = diff = readA = readB = 0
        
        while True:
            total += 1
            if icA is None:
                try:
                    rA = cA.next()
                except StopIteration:
                    pass
                else:
                    readA += 1
                    icA = rA[self.indexcol]
            if icB is None:
                try:
                    rB = cB.next()
                except StopIteration:
                    pass
                else:
                    readB += 1
                    icB = rB[self.indexcol]
                    
            if (icA is None) and (icB is None):
                break

            if icB is None or icA is not None and icA < icB:
                print "A ,%i: [%s]" % (icA, rA.get("name",""))
                icA = None
                old += 1
            elif icA is None or icA > icB:
                print " B,%i: [%s]" % (icB, rB.get("name",""))
                icB = None
                new += 1
            else:
                sA = set(rA)-{"_id"}
                sB = set(rB)-{"_id"}
                AnotB = sA-sB
                BnotA = sB-sA
                ABdiff = [k for k in sA&sB if rA[k] != rB[k]]
                nameA, nameB = rA.get("name",""), rB.get("name","")
                name = nameA if nameA == nameB else "A:[%s]/B:[%s]" % (nameA,nameB)
                if AnotB or BnotA or ABdiff:
                    descr = ["-%s" % k for k in AnotB]+["+%s" % k for k in BnotA]+["*%s[%s=>%s]" % (k,str(rA[k])[:20],str(rB[k])[:20]) for k in ABdiff]
                    print "AB,%i: [%s] %s" % (icA, name, ", ".join(descr))
                    diff += 1
                icA = icB = None
                
        print "---------------"
        print "Table [%s]: %i records checked, %i disappeared, %i appeared, %i changed" % (self.tablename, total, old, new, diff)
        print "==============="




def main():
    import optparse
    parser = optparse.OptionParser()
    
    parser.add_option("--CA", dest="connectionA",
                      help="Backend A connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    parser.add_option("--CB", dest="connectionB",
                      help="Backend B connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")

    parser.add_option("--BA", dest="backend_classA", default="mongo",
                      help="database A backend (amongst: %s)" % (", ".join(bta.backend.Backend.backends.keys())))
    parser.add_option("--BB", dest="backend_classB", default="mongo",
                      help="database B backend (amongst: %s)" % (", ".join(bta.backend.Backend.backends.keys())))

    
    parser.add_option("--only", dest="only", default="",
                      help="Diff only TABLENAME", metavar="TABLENAME")
    
    options, args = parser.parse_args()

    
    if options.connectionA is None:
        parser.error("Missing connection string A (--CA)")
    if options.connectionA is None:
        parser.error("Missing connection string B (--CB)")
    

    backend_classA = bta.backend.Backend.get_backend(options.backend_classA)
    options.connection = options.connectionA # XXX hack
    options.backendA = backend_classA(options)
    
    backend_classB = bta.backend.Backend.get_backend(options.backend_classB)
    options.connection = options.connectionB # XXX hack
    options.backendB = backend_classB(options)
    
    for tablename,otherval,indexcol in [ ("sd_table", ["sdtable", "sd_table", "sd"], "id"),
                                         ("datatable", ["datatable", "data"], "DNT_col"), 
                                         ]:
        if not options.only or options.only.lowers() in otherval:
            differ = TableDiff(options, tablename, indexcol)
            differ.run()

if __name__ == "__main__":
    main()

