
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

def test_present():
    r = Field("toto").present()
    lr = r.build(LDAPReqBuilder)
    assert lr == "(toto=*)"

def test_absent():
    r = Field("toto").absent()
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


def test_flags():
    r = Field("userAccountControl").flag_on("normalAccount")
    lr = r.build(LDAPReqBuilder)
    assert lr == "(userAccountControl:1.2.840.113556.1.4.803:=512)"
    r = Field("userAccountControl").flag_off("passwordExpired")
    lr = r.build(LDAPReqBuilder)
    assert lr == "(!userAccountControl:1.2.840.113556.1.4.804:=8388608)"


def test_all():
    r = Field("toto").present()
    r |= Field("userAccountControl").flag_on("smartcardRequired")
    r &= Field("titi") == "tutu"
    lr = r.build(LDAPReqBuilder)
    assert lr == "(&(|(toto=*)(userAccountControl:1.2.840.113556.1.4.803:=262144))(titi=tutu))"

