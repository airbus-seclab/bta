#! /usr/bin/env python

import pymongo
from ntds2db import Mongo
import time

def win2time(x):
    return time.ctime(int(x)-11644473600)

def do_timeline(options):
    options.records=[]
    db = Mongo(options)
    col = db.db[options.tablename]
    
    c = col.find({"whenChanged":{"$exists":True}})
    for r in c:
        print u"%7s %s %s %s %s" % (r["RecId"],
                                    win2time(r["whenCreated"]),
                                    win2time(r["whenChanged"]),
                                    r.get("name","--"),
                                    r.get("distinguishedName","--"))
    



def main():
    import optparse
    parser = optparse.OptionParser()
    
    parser.add_option("-C", dest="connection",
                      help="PostGreSQL connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    parser.add_option("-t", dest="tablename",
                      help="table name to create in database", metavar="TABLENAME")

    options, args = parser.parse_args()

    
    if options.tablename is None:
        parser.error("Missing table name (-t)")
    if options.connection is None:
        parser.error("Missing connection string (-C)")

    do_timeline(options)

if __name__ == "__main__":
    main()
