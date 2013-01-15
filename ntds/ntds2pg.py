#! /usr/bin/env python

import sys
import psycopg2

def win2epoch(x):
    return x-11644473600

class DBNormalization(object):
    db_coltype = None
    db_place = "%s"
    def norm(self, val):
        return val
    def to_db(self, val):
        return val

class NormEmpty(DBNormalization):
    def to_db(self, val):
        if not val:
            return None
        return self.norm(val)

class Text(DBNormalization):
    db_coltype = "text"

class Int(NormEmpty):
    db_coltype = "int NULL"
    def norm(self, val):
        return int(val)

class BigInt(Int):
    db_coltype = "bigint NULL"

class Timestamp(Int):
    db_coltype = "timestamp NULL"
    db_place = "to_timestamp(%s)"
    def norm(self, val):
        val = int(val)
        if val  > 259199220266:
            return None
        return win2epoch(val)


class Records:
    @classmethod
    def get(cls, name):
        return getattr(cls, name)
    datatable = [
        # db col name # dt name # db type 
        ("RecId", "DNT_col", BigInt()),
        ("ParentRecId", "PDNT_col", BigInt()),
        ("RecordTime", "time_col", Timestamp()),
        ("LDAPDisplayName", "ATTm131532", Text()),
        ("attributeID", "ATTc131102", BigInt()),
#        ("attributeTypes", "ATTc1572869", Text()),
        ("attributeSyntax", "ATTc131104", Text()),
        ]
    sdtable = [
        # db col name # dt name # db type 
        ("id", "sd_id", BigInt()),
        ("hash", "sd_hash", Text()),
        ("refcount", "sd_refcount", BigInt()),
        ("value", "sd_value", Text())
        ]



class Backend(object):
    pass


class PostGreSQL(Backend):
    def __init__(self, options):
        self.cnxstr = options.connection
        self.cnx = psycopg2.connect(self.cnxstr)
        self.c = self.cnx.cursor()
        self.table = options.tablename
        self.records = options.records
        self.rnum = len(self.records)
        self.create_table()
        self.sqlinsert = "insert into %s values (%s)" % (self.table, ",".join([x[2].db_place for x in self.records]))


    def commit(self):
        self.cnx.commit()
        
    def create_table(self):
        s = []
        for col,_,dbt in self.records:
            s.append("%s %s" % (col, dbt.db_coltype))

        sql = "create table %s ( %s )" % (self.table, ",".join(s))
        self.c.execute(sql)

    def insert(self, values):
        self.c.execute(self.sqlinsert, values)
        


def parse_header(options, head):
    nrec = len(options.records)
    n = 0
    fmt = [-1]*nrec
    h2pos = dict([(x[1],(i,x[2])) for i,x in enumerate(options.records)])
    
    for i,h in enumerate(head.strip().split("\t")):
        if h in h2pos:
            pos,typ = h2pos[h]
            fmt[pos] = i,typ
            n += 1
            if n == nrec:
                break
    else:
        raise Exception("Did not find some headers: fmt=%r" % fmt)
    return fmt

def extract(fmt, line):
    sl = line.split("\t")
    return [typ.to_db(sl[i]) for i,typ in fmt]

def parse_table(options):

    f = open(options.datatable)
    head = f.readline()

    print "Parsing header line"
    fmt = parse_header(options, head)

    print "Parsing table lines"
    while True:
#    for i in range(50):
        l = f.readline()
        if not l:
            break
        sys.stdout.write(".")
        values = extract(fmt, l)
        options.db.insert(values)
    print "done"

def main():
    import optparse
    parser = optparse.OptionParser()
    
    parser.add_option("-C", dest="connection",
                      help="PostGreSQL connection string. Ex: 'dbname=test user=john')", metavar="CNX")
    parser.add_option("-f", dest="datatable",
                      help="datatable extracted by libesedb from ntds.dit", metavar="FNAME")

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
        parser.error("Missing PostGreSQL connection string (-C)")

    options.records = Records.get(options.tabletype)
    options.db = PostGreSQL(options)
    
    parse_table(options)

    options.db.commit()

if __name__ == "__main__":
    main()
