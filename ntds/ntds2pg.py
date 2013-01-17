#! /usr/bin/env python

import sys
import psycopg2
import pymongo
import itertools

def win2epoch(x):
    return x-11644473600

def dbsanecolname(x):
    return x.replace("-","_")

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
# OBJ_col RDNtyp_col cnt_col ab_cnt_col NCDNT_col IsVisibleInAB recycle_time_col Ancestors_col
        ("lDAPDisplayName", "ATTm131532", Text()),
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

ATTRIBUTE_ID="ATTc131102"
ATTRIBUTE_SYNTAX="ATTc131104"
LDAP_DISPLAY_NAME="ATTm131532"

attsyntax2type = {
#    524290: BigInt, #ID
    524293: Text, #printable name
    524298: Text, # GUID
#    524297: BigInt,
    524299: Timestamp, #timestamp
    524300: Text, #names
    524304: Timestamp, # time
}

def syntax_to_type(s):
    return attsyntax2type.get(s, Text)



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
        self.records = options.records[:]

    def commit(self):
        pass
        
    def create_table(self):
        pass

    def add_col(self, coldef):
        self.records.append(coldef)


@Backend.register("postgresql")
class PostGreSQL(Backend):
    def __init__(self, options):
        Backend.__init__(self, options)
        self.cnxstr = options.connection
        self.cnx = psycopg2.connect(self.cnxstr)
        self.c = self.cnx.cursor()
        self.table = options.tablename
        self.records = options.records[:]
        self.rnum = len(self.records)

    def commit(self):
        self.cnx.commit()

    def create_table(self):
        s = []
        for col,_,dbt in self.records[:1600]:
            s.append("%s %s" % (col, dbt.db_coltype))

        sql = "create table %s ( %s )" % (self.table, ",".join(s))
        self.c.execute(sql)
        self.sqlinsert = "insert into %s values (%s)" % (self.table, ",".join([x[2].db_place for x in self.records[:1600]]))

    def insert(self, values):
        self.c.execute(self.sqlinsert, values[:1600])
        

@Backend.register("mongo")
class Mongo(Backend):
    def __init__(self, options):
        Backend.__init__(self, options)
        self.colname = options.tablename
        ip,port,self.dbname,_ = (options.connection+":::").split(":",3)
        ip = ip if ip else "127.0.0.1"
        port = int(port) if port else 27017
        self.cnxstr = (ip,port)
        self.cnx = pymongo.Connection(*self.cnxstr)
        self.db = self.cnx[self.dbname]
    def create_table(self):
        self.fields = [x[0] for x in self.records]
        self.col = self.db.create_collection(self.colname)
    def insert(self, values):
        d = dict(itertools.compress(zip(self.fields, values), values))
        id = self.col.insert(d)
    def count(self):
        return self.col.count()
    

def parse_header(options, head):
    nrec = len(options.records)
    fmt = [None]*nrec
    h2pos = dict([(x[1],(i,x[2])) for i,x in enumerate(options.records)])
    
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
                typ = syntax_to_type(int(sl[asy]))()
                nam = dbsanecolname(sl[ldn])
                options.db.add_col((nam, att, typ))
                fmt.append((pos,typ))
        if unkcd:
            print "Still %i unresolved cols" % len(unkcd)
            for pos,att in unkcd.itervalues():
                typ = Text()
                options.db.add_col((dbsanecolname(att), att, typ))
                fmt.append((pos, typ))
        else:
            print "All cols resolved"
    return fmt

def extract(fmt, line):
    sl = line.split("\t")
    return [typ.to_db(sl[i]) for i,typ in fmt]

def parse_table(options):

    f = open(options.datatable)
    head = f.readline()

    print "Parsing header line"
    fmt = parse_header(options, head)

    options.db.create_table()

    print "Parsing table lines"
    while True:
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
    

    db_backend = Backend.get_backend(options.backend)
                     


    options.records = Records.get(options.tabletype)
    options.db = db_backend(options)
    
    parse_table(options)

    options.db.commit()

if __name__ == "__main__":
    main()
