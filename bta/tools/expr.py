# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

    
class Expr(object):
    def __init__(self, op1, op, op2):
        self.op1 = op1
        self.op = op
        self.op2 = op2
    def __and__(self, other):
        return Expr(self, "_and_", other)
    def __or__(self, other):
        return Expr(self, "_or_", other)
    def __eq__(self, other):
        return Expr(self, "_eq_", other)
    def __ne__(self, other):
        return Expr(self, "_ne_", other)
    def __repr__(self):
        return "<Expr: (%r %s %r)>" % (self.op1, self.op, self.op2)
    def build(self, builder):
        op1 = self.op1.build(builder) if hasattr(self.op1, "build") else self.op1
        op2 = self.op2.build(builder) if hasattr(self.op2, "build") else self.op2
        
        return getattr(builder, self.op)(op1, op2)

class Field(object):
    def __init__(self, name, flags=None):
        self.name = name
        self.flags = flags
    def __eq__(self, other):
        return Expr(self, "_eq_", other)
    def __ne__(self, other):
        return Expr(self, "_ne_", other)
    def __repr__(self):
        return "<Field: %r>" % self.name
    def build(self, builder):
        return builder._field_(self.name, self.flags)



class Builder(object):
    pass

class FormulaBuilder(Builder):
    def __init__(self, formula=""):
        Builder.__init__(self)
        self.formula = formula
    def __str__(self):
        return self.formula
    def __repr__(self):
        return "<formula builder: %s>" % self

    @classmethod
    def _field_(cls, name, flags):
        n = repr(name)
        if flags:
            n += "."+repr(flags)
        return cls(repr(name))
    @classmethod
    def _and_(cls, op1, op2):
        return cls("(%s) && (%s)" % (op1, op2))
    @classmethod
    def _or_(cls, op1, op2):
        return cls("(%s) || (%s)" % (op1, op2))
    @classmethod
    def _eq_(cls, op1, op2):
        return cls("(%s) == (%s)" % (op1, op2))
    @classmethod
    def _ne_(cls, op1, op2):
        return cls("(%s) != (%s)" % (op1, op2))



