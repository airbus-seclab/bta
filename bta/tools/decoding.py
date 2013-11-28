# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

import struct
import bta.datatable

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

def decode_ancestors(ancestors):
    nb_ancestors = len(ancestors)/4
    id_ancestors = struct.unpack_from('i'*nb_ancestors,ancestors)
    return id_ancestors

def decode_OID(OID_interger):
    return "%s%s"%(bta.datatable.OIDPrefix(OID_interger&0xffff0000).to_json(), OID_interger&0xffff)
    
    
