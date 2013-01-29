import struct

def decode_sid(s):
    rev,subauthnb = struct.unpack_from("<BB",s)
    rev &= 0x0f
    iah,ial = struct.unpack_from(">IH", s[2:])
    ia = (iah<<16)|ial
    subauth = struct.unpack_from("<%iI" % subauthnb, s[8:])
    sid = "S-%i-%s" % (rev, "-".join(["%i"%x for x in ((ia,)+subauth)]))
    return sid

def decode_guid(s):
    part1 =  "%08X-%04X-%04X-" % struct.unpack("<IHH", s[:8])
    part2 = "%04X-%08X%04X" % struct.unpack(">HIH", s[8:])
    return part1+part2
