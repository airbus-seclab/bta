
import pytest
from bta.tools.expr import *

def test_field():
    f = Field("foobar")
    assert f.name == "foobar"

def test_cond():
    f = Field("foobar")
    e = f == 123
    assert isinstance(e, Cond)
    assert e.op1 == f
    assert e.op2 == 123
    assert e.op == "_eq_"
    e = f != 123
    assert e.op1 == f
    assert e.op2 == 123
    assert e.op == "_ne_"

    e = f.present()
    assert e.op1 == f
    assert e.op == "_present_"
    assert e.op2 == None
    e = f.absent()
    assert e.op1 == f
    assert e.op == "_absent_"
    assert e.op2 == None

    e = f.flag_on("x")
    assert e.op1 == f
    assert e.op == "_flagon_"
    assert e.op2 == "x"

    e = f.flag_off("y")
    assert e.op1 == f
    assert e.op == "_flagoff_"
    assert e.op2 == "y"


def test_expr():
    e = (Field("toto") == "tata")
    assert repr(e) == "<Cond: <Field: 'toto'> _eq_ 'tata'>"
    e = (Field("toto") == "tata") | (Field("titi") != "tutu")
    assert repr(e) == "<Expr: (<Cond: <Field: 'toto'> _eq_ 'tata'> _or_ <Cond: <Field: 'titi'> _ne_ 'tutu'>)>"
    e = (Field("toto") == "tata") & (Field("titi") != "tutu")
    assert repr(e) == "<Expr: (<Cond: <Field: 'toto'> _eq_ 'tata'> _and_ <Cond: <Field: 'titi'> _ne_ 'tutu'>)>"
    e = (Field("toto").present()) & (Field("titi").absent())
    assert repr(e) == "<Expr: (<Cond: <Field: 'toto'> _present_> _and_ <Cond: <Field: 'titi'> _absent_>)>"

def test_build():
    e = (Field("toto") == Field("titi")) | (Field("tutu") == "tata")
    b = e.build(FormulaBuilder)
    assert b.formula == "('toto' == 'titi') || ('tutu' == tata)"
    e = (Field("toto") == "tata") & (Field("titi") != "tutu")
    b = e.build(FormulaBuilder)
    assert b.formula == "('toto' == tata) && ('titi' != tutu)"
    e = (Field("toto").present()) & (Field("titi").absent())
    b = e.build(FormulaBuilder)
    assert b.formula == "('toto' exists) && ('titi' does not exist)"
    e = ( (Field("toto").flag_on("123") & Field("tata").flag_off("456")) | 
          (Field("titi").flag_on("789") & Field("tutu").flag_off("abc")) )
    b = e.build(FormulaBuilder)
    assert b.formula == "(('toto' & 123 != 0) && ('tata' & 456 == 0)) || (('titi' & 789 != 0) && ('tutu' & abc == 0))"
