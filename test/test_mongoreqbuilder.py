
import pytest
from bta.backend.mongo import *
from bta.tools.expr import *

def test_eq():
    r = Field("toto")=="tata"
    mr = r.build(MongoReqBuilder)
    assert mr == { "toto": "tata" }

def test_ne():
    r = Field("toto")!="tata"
    mr = r.build(MongoReqBuilder)
    assert mr == { "toto":{"$ne":"tata" } }

def test_exists():
    r = Field("toto")!=None
    mr = r.build(MongoReqBuilder)
    assert mr == { "toto":{"$exists":True } }

def test_does_not_exists():
    r = Field("toto")==None
    mr = r.build(MongoReqBuilder)
    assert mr == { "toto":{"$exists":False } }

def test_and():
    r = (Field("toto")=="tata") & (Field("titi")!="tutu")
    mr = r.build(MongoReqBuilder)
    assert mr == { "toto": "tata",
                   "titi":{"$ne":"tutu" } }

def test_and():
    r = (Field("toto")=="tata") | (Field("titi")!="tutu")
    mr = r.build(MongoReqBuilder)
    assert mr == { "$or" : [ { "toto": "tata" },
                             { "titi":{"$ne":"tutu" } } ] }

def test_all():
    r = (Field("toto")=="tata") | (Field("titi")!="tutu")
    r &= Field("foo") == "bar"
    mr = r.build(MongoReqBuilder)
    assert mr == { "foo": "bar",
                   "$or" : [ { "toto": "tata" },
                             { "titi":{"$ne":"tutu" } } ] }
    




