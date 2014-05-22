# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import shlex
import functools
import os
import logging

log = logging.getLogger("bta.rpnedit")

def stackify(f):
    @functools.wraps(f)
    def stackified(self, f=f):
        n = f.func_code.co_argcount
        # pylint: disable=protected-access
        self._apply(f, n)
    return stackified

class RPNFilenameEditor(object):
    #pylint: disable=no-self-argument,no-member
    def __init__(self, prog):
        self._prog = None
        self._new_prog(prog)
        self._stack = []

    def _new_prog(self, prog):
        log.debug("RPN: new prog=[%s]" % prog)
        self._prog = list(shlex.split(prog))
    def _run_prog(self):
        for w in self._prog:
            self._eval(w)
    def __call__(self, *args):
        log.debug("### RPN: called on %r" % (args,))
        self._stack = list(args)
        self._run_prog()
        log.debug("RPN: final stack: %r" % self._stack)
        return self._stack[-1]
    def _push(self, word):
        self._stack.append(word)
    def _eval(self, word):
        log.debug("RPN: [%s] on %r" % (word, self._stack))
        if not word.startswith("_") and hasattr(self, word):
            getattr(self, word)()
        else:
            self._push(word)
    def _eval_string(self, s):
        for w in shlex.split(s):
            self._eval(w)
        return self
    def _apply(self, f, arity):
        op = self._stack[-arity:]
        self._stack = self._stack[:-arity]
        self._stack.append(f(*op))
    def dup(self):
        self._stack.append(self._stack[-1])
    def drop(self):
        self._stack.pop()
    def swap(self):
        self._stack[-2],self._stack[-1] = self._stack[-1],self._stack[-2]
    @stackify
    def basename(s):
        return os.path.basename(s)
    @stackify
    def dirname(s):
        return os.path.dirname(s)
    @stackify
    def pathjoin(s1,s2):
        return os.path.join(s1, s2)
    @stackify
    def rmext(s):
        p = s.rfind(".")
        if p < 0:
            return s
        return s[:p]
    @stackify
    def rmtaildir(s):
        p = s.rfind("/")
        if p < 0:
            return s
        return s[:p]
    @stackify
    def rmheaddir(s):
        p = s.find("/")
        if p < 0:
            return s
        return s[p+1:]
    @stackify
    def rmallext(s):
        p = s.find(".")
        if p < 0:
            return s
        return s[:p]
    @stackify
    def tail(s, n):
        return s[-int(n):]
    @stackify
    def cuttail(s, n):
        return s[:-int(n)]
    @stackify
    def head(s, n):
        return s[:int(n)]
    @stackify
    def cuthead(s, n):
        return s[int(n):]
    @stackify
    def extract(s, a, b):
        return s[int(a):int(b)]
    @stackify
    def plus(s1, s2):
        return s1+s2
    @stackify
    def replace(s, s1, s2):
        return s.replace(s1, s2)
    @stackify
    def remove(s, s1):
        return s.replace(s1, "")
    @stackify
    def lower(s):
        return s.lower()
    @stackify
    def upper(s):
        return s.upper()


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("program")
    parser.add_argument("--print-stack", action="store_true")
    parser.add_argument("--stacks", nargs="+", default=[None])

    options = parser.parse_args()
    for stk in options.stacks:
        prog = RPNFilenameEditor(options.program)
        res = prog() if stk is None else prog(stk)

        if options.print_stack:
            l = len(prog._stack)-1
            for i,v in enumerate(prog._stack):
                print "%3i: %r" % (l-i,v)
        if stk is None:
            print "==>", res
        else:
            print "%-20s <== %s" % (res, stk)

if __name__ == "__main__":
    main()
