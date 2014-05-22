# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import struct
import bta.datatable
from datetime import datetime, timedelta

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

def decode_ReplPropMeta(bin_data):
    def insert_dash(string, indexes):
        final_string=string
        count=0
        for index in indexes:
            final_string = final_string[:index+count] + '-' + final_string[index+count:]
            count += 1
        return final_string
    def shift_eight_first(string):
        final_string=""
        for i in [6,4,2,0,10,8,14,12]:
            final_string+=string[i:i+2]
        final_string+=string[16:]
        return final_string
    nb_of_prop = struct.unpack_from('l',bin_data,8)[0]
    list_prop=list()
    unpack_string='iil16sll'
    for i in range(nb_of_prop):
        (oid, version, date, objectId, OrgUSN, LocUSN) = struct.unpack_from(unpack_string,bin_data,16+i*struct.calcsize(unpack_string))
        list_prop.append({"OID":decode_OID(oid),
                          "version":version,
                          "date":datetime(1601,1,1,1,0,0) + timedelta(seconds=date),
                          "objectId":insert_dash(shift_eight_first(objectId.encode('hex')),[8,12,16,20]),
                          "LocUSN":LocUSN,
                          "OrgUSN":OrgUSN})
    return list_prop
