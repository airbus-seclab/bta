# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

import sys
import time, datetime
import struct
from collections import defaultdict

def decode_sid(s, endianness="<"):
    "Depending on the source, last sub-authority will be little or big endian"
    rev,subauthnb = struct.unpack_from("<BB",s)
    rev &= 0x0f
    iah,ial = struct.unpack_from(">IH", s[2:])
    ia = (iah<<16)|ial
    if subauthnb > 0:
        subauth = struct.unpack_from("<%iI" % (subauthnb-1), s[8:-4])
        subauth += struct.unpack_from("%sI"%endianness, s[-4:])
    else:
        subauth = ()
    sid = "S-%i-%s" % (rev, "-".join(["%i"%x for x in ((ia,)+subauth)]))
    return sid

def decode_guid(s):
    part1 =  "%08x-%04x-%04x-" % struct.unpack("<IHH", s[:8])
    part2 = "%04x-%08x%04x" % struct.unpack(">HIH", s[8:])
    return part1+part2


class Registry(object):
    registry = defaultdict(dict)
    @classmethod
    def register(cls, **kargs):
        def do_reg(f, cls=cls, kargs=kargs):
            cls.registry[cls.__name__][f.__name__]=kargs
            return f
        return do_reg
    
    @classmethod
    def register_ref(cls, obj, key="__name__"):
        cls.registry[cls.__name__][getattr(obj, key)]=obj
        return obj
    
    @classmethod
    def get_all(cls):
        return cls.registry[cls.__name__]
    @classmethod
    def get(cls, name, default=None):
        return cls.registry[cls.__name__].get(name, default)
    
    @classmethod
    def iterkeys(cls):
        return iter(cls.registry[cls.__name__])
    @classmethod
    def iteritems(cls):
        return cls.registry[cls.__name__].iteritems()
    @classmethod
    def itervalues(cls):
        return cls.registry[cls.__name__].itervalues()


def stderr_progress_bar(total, desc="Progress", step=100, obj="rec"):
    t0 = time.time()
    tprevstep = t0-0.01 # t0-tprevstem must always be != 0
    i = 0
    iprevstep = 0
    iprevcall = -1
    while True:
        new_i = yield
        i = new_i if new_i is not None else i+1
        if iprevcall/step != i/step or i >= total:
            t = time.time()
            avg = i/(t-t0)
            inst = (i-iprevstep)/(t-tprevstep)
            eta = datetime.timedelta(seconds=int((total-i)/inst))
            elapsed = datetime.timedelta(seconds=int(t-t0))
            tprevstep = t
            iprevstep = i
            sys.stderr.write("\033[A\033[K%s: %i / %i  --  avg=%.2f %s/s inst=%.2f %s/s  --  ETA=%s elapsed=%s\n" % 
                             (desc, i, total, avg, obj, inst, obj, eta, elapsed))
        iprevcall = i
