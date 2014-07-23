
import pytest
from bta.backend.ldap_backend import *
from bta.tools.expr import *

def test_eq():
    r = Field("toto")=="tata"
    lr = r.build(LDAPReqBuilder)
    assert lr == "(toto=tata)"

def test_ne():
    r = Field("toto")!="tata"
    lr = r.build(LDAPReqBuilder)
    assert lr == "(!toto=tata)"

def test_exists():
    r = Field("toto")!=None
    lr = r.build(LDAPReqBuilder)
    assert lr == "(toto=*)"

def test_does_not_exists():
    r = Field("toto")==None
    lr = r.build(LDAPReqBuilder)
    assert lr == "(!toto=*)"

def test_and():
    r = (Field("toto")=="tata") & (Field("titi")!="tutu")
    lr = r.build(LDAPReqBuilder)
    assert lr == "(&(toto=tata)(!titi=tutu))"

def test_and():
    r = (Field("toto")=="tata") | (Field("titi")!="tutu")
    lr = r.build(LDAPReqBuilder)
    assert lr == "(|(toto=tata)(!titi=tutu))"

def test_all():
    r = (Field("toto")=="tata") | (Field("titi")!="tutu")
    r &= Field("foo") == "bar"
    lr = r.build(LDAPReqBuilder)
    assert lr == "(&(|(toto=tata)(!titi=tutu))(foo=bar))"




