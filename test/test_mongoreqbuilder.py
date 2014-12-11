
import pytest
from bta.backend.mongo import *
from bta.tools.expr import *

def test_eq():
    r = Field("toto")=="tata"
    mr = r.build(MongoReqBuilder())
    assert mr == { "toto": "tata" }

def test_ne():
    r = Field("toto")!="tata"
    mr = r.build(MongoReqBuilder())
    assert mr == { "toto":{"$ne":"tata" } }

def test_present():
    r = Field("toto").present()
    mr = r.build(MongoReqBuilder())
    assert mr == { "toto":{"$exists":True } }

def test_absent():
    r = Field("toto").absent()
    mr = r.build(MongoReqBuilder())
    assert mr == { "toto":{"$exists":False } }

def test_and():
    r = (Field("toto")=="tata") & (Field("titi")!="tutu")
    mr = r.build(MongoReqBuilder())
    assert mr == { "toto": "tata",
                   "titi":{"$ne":"tutu" } }

def test_and():
    r = (Field("toto")=="tata") | (Field("titi")!="tutu")
    mr = r.build(MongoReqBuilder())
    assert mr == { "$or" : [ { "toto": "tata" },
                             { "titi":{"$ne":"tutu" } } ] }



def test_flags():
    r = Field("userAccountControl").flag_on("normalAccount")
    mr = r.build(MongoReqBuilder())
    assert mr == { "userAccountControl.flags.normalAccount" : True }
    r = Field("userAccountControl").flag_off("passwordExpired")
    mr = r.build(MongoReqBuilder())
    assert mr == { "userAccountControl.flags.passwordExpired" : False }


def test_all():
    r = (Field("toto")=="tata") | (Field("titi")!="tutu")
    r &= Field("foo") == "bar"
    r |= Field("userAccountControl").flag_on("smartcardRequired")
    mr = r.build(MongoReqBuilder())
    assert mr == { 
        "$or" : [
            { "foo": "bar",
              "$or" : [ { "toto": "tata" },
                        { "titi":{"$ne":"tutu" } } ] },
            { "userAccountControl.flags.smartcardRequired" : True }
        ]
    }
    




