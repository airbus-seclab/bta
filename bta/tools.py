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
