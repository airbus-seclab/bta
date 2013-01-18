#! /usr/bin/env python

import sys
import itertools

import ntds.backend.mongo

def win2epoch(x):
    return x-11644473600

def dbsanecolname(x):
    return x.replace("-","_")


class Columns:
    @classmethod
    def get(cls, name):
        return getattr(cls, name)
    datatable = [
        # db col name # dt name # db type 
        ("RecId", "DNT_col", "Int"),
        ("ParentRecId", "PDNT_col", "Int"),
        ("RecordTime", "time_col", "Timestamp"),
# OBJ_col RDNtyp_col cnt_col ab_cnt_col NCDNT_col IsVisibleInAB recycle_time_col Ancestors_col
        ("lDAPDisplayName", "ATTm131532", "Text"),
        ("attributeID", "ATTc131102", "Int"),
#        ("attributeTypes", "ATTc1572869", "Text"),
        ("attributeSyntax", "ATTc131104", "Text"),
        ]
    sdtable = [
        # db col name # dt name # db type 
        ("id", "sd_id", "Int"),
        ("hash", "sd_hash", "Text"),
        ("refcount", "sd_refcount", "Int"),
        ("value", "sd_value", "Text")
        ]

ATTRIBUTE_ID="ATTc131102"
ATTRIBUTE_SYNTAX="ATTc131104"
LDAP_DISPLAY_NAME="ATTm131532"

attsyntax2type = {
#    524290: BigInt, #ID
    524293: "Text", #printable name
    524298: "Text", # GUID
#    524297: "Int",
    524299: "Timestamp", #timestamp
    524300: "Text", #names
    524304: "Timestamp", # time
}

def syntax_to_type(s):
    return attsyntax2type.get(s, "Text")



def parse_header(options, head):
    nrec = len(options.columns)
    fmt = [None]*nrec
    h2pos = dict([(x[1],(i,x[2])) for i,x in enumerate(options.columns)])
    
    split_head = head.strip().split("\t")
    unk_col = []
    for i,h in enumerate(split_head):
        if h in h2pos:
            pos,typ = h2pos[h]
            fmt[pos] = i,typ
        else:
            unk_col.append((i,h))
    
    if None in fmt:        
        raise Exception("Did not find some headers: fmt=%r" % fmt)

    if unk_col:
        print "Resolving %i unknown columns" % len(unk_col)
        f = open(options.datatable)
        f.readline() # seek after header
        unkcd = dict([(h[4:],(i,h)) for i,h in unk_col if h.startswith("ATT")])
        aid = split_head.index(ATTRIBUTE_ID)
        asy = split_head.index(ATTRIBUTE_SYNTAX)
        ldn = split_head.index(LDAP_DISPLAY_NAME)
        if aid < 0 or asy < 0 or ldn < 0:
            raise Exception("Did not find %s or %s or %s" % (ATTRIBUTE_ID, ATTRIBUTE_SYNTAX, LDAP_DISPLAY_NAME))
        while unkcd:
            l = f.readline()
            if not l:
                break
            sl = l.strip().split("\t")
            pos,att = unkcd.pop(sl[aid], (None,None))
            if att is not None:
                typ = syntax_to_type(int(sl[asy]))
                nam = dbsanecolname(sl[ldn])
                options.db.add_col((nam, att, typ))
                fmt.append((pos,typ))
        if unkcd:
            print "Still %i unresolved cols" % len(unkcd)
            for pos,att in unkcd.itervalues():
                typ = "Text"
                options.db.add_col((dbsanecolname(att), att, typ))
                fmt.append((pos, typ))
        else:
            print "All cols resolved"
    return fmt

def extract(fmt, line):
    sl = line.split("\t")
#    return [typ.to_db(sl[i]) for i,typ in fmt]
    return [sl[i] for i,typ in fmt]

def parse_table(options):

    f = open(options.datatable)
    head = f.readline()

    print "Parsing header line"
    fmt = parse_header(options, head)

    options.db.create_table()

    print "Parsing table lines"
    i = 0
    try:
        while True:
            l = f.readline()
            if not l:
                break
            i+=1
            if i%100 == 0:
                sys.stderr.write("         \r%i %i" % (i, options.db.count()))
            values = extract(fmt, l)
            options.db.insert(values)
    except KeyboardInterrupt:
        print "\rInterrupted by user"
    else:
        print "\rdone           "

def main():
    import optparse
    parser = optparse.OptionParser()
    
    parser.add_option("-C", dest="connection",
                      help="PostGreSQL connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    parser.add_option("-f", dest="datatable",
                      help="datatable extracted by libesedb from ntds.dit", metavar="FNAME")
    parser.add_option("-B", dest="backend", default="mongo",
                      help="database backend (amongst mongo, postgresql)")
    parser.add_option("-t", dest="tablename",
                      help="table name to create in database", metavar="TABLENAME")
    parser.add_option("-T", dest="tabletype", default="datatable",
                      help="type of table to parse (amongst 'datatable', 'sdtable')",
                      metavar="TYPE")

    options, args = parser.parse_args()

    
    if options.datatable is None:
        parser.error("Missing datatable filename (-f)")
    if options.tablename is None:
        parser.error("Missing table name (-t)")
    if options.connection is None:
        parser.error("Missing connection string (-C)")
    

    db_backend = ntds.backend.Backend.get_backend(options.backend)
                     


    options.columns = Columns.get(options.tabletype)
    options.db = db_backend(options)
    
    parse_table(options)

    options.db.commit()

if __name__ == "__main__":
    main()
