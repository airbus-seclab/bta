
import pytest
from bta.tools.expr import *

def test_field():
    f = Field("foobar")
    e = f == 123
    assert e.op1 == f
    assert e.op2 == 123
    assert e.op == "_eq_"
    e = f != 123
    assert e.op1 == f
    assert e.op2 == 123
    assert e.op == "_ne_"

def test_expr():
    e = (Field("toto") == "tata")
    assert repr(e) == "<Expr: (<Field: 'toto'> _eq_ 'tata')>"
    e = (Field("toto") == "tata") | (Field("titi") != "tutu")
    assert repr(e) == "<Expr: (<Expr: (<Field: 'toto'> _eq_ 'tata')> _or_ <Expr: (<Field: 'titi'> _ne_ 'tutu')>)>"
    e = (Field("toto") == "tata") & (Field("titi") != "tutu")
    assert repr(e) == "<Expr: (<Expr: (<Field: 'toto'> _eq_ 'tata')> _and_ <Expr: (<Field: 'titi'> _ne_ 'tutu')>)>"

def test_build():
    e = (Field("toto") == Field("titi")) | (Field("tutu") == "tata")
    b = e.build(FormulaBuilder)
    assert b.formula == "(('toto') == ('titi')) || (('tutu') == (tata))"
    e = (Field("toto") == "tata") & (Field("titi") != "tutu")
    b = e.build(FormulaBuilder)
    assert b.formula == "(('toto') == (tata)) && (('titi') != (tutu))"


