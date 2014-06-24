# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import pytest
import mongomock
from mongomock import ObjectId
import argparse
import datetime
import dateutil.parser
import bta.docstruct
import bta.backend.mongo


def Date(x):
    return datetime.datetime.fromtimestamp(x/1000)

def ISODate(x):
    return dateutil.parser.parse(x)

def NumberLong(x):
    return x

false = False
true = True


## Helpers


def run_miner(miner, db, **kargs):
    options = argparse.Namespace(verbose=0,**kargs)
    doc = bta.docstruct.RootDoc("test")
    backend = bta.backend.mongo.Mongo(options, database=db)
    m = miner(backend)
    m.run(options, doc)
    return doc


## Fixtures

@pytest.fixture(scope="session")
def normal_db():
    cnx = mongomock.Connection()
    db = cnx.db
    db.log.insert( 
        { "_id" : ObjectId( "6426f8ea2c4f057c661f2c3d" ), 
          "actions" : [ { "date" : Date( 1390841509307 ), "action" : "Opened ESEDB file [/tmp/ntds.dit]" }, 
                        { "date" : Date( 1390841509307 ), "action" : "Start of importation of [sd_table]" }, 
                        { "date" : Date( 1390841509385 ), "action" : "End of importation of [sd_table]. 94 records." }, ], 
          "args" : [ "/tmp/vbta/bin/ntds2db", "-C", "::test", "/tmp/ntds.dit" ], 
          "date" : Date( 1390841509288 ), 
          "program" : "/tmp/vbta/bin/ntds2db", 
          "version" : "0.3" })
    return db
