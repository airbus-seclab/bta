# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import struct
import bta.tools.decoding
from bta.tools.flags import Flags, Enums

# Heavily inspired by reading WinNT.h

class SE:
    SE_OWNER_DEFAULTED               = 0x0001
    SE_GROUP_DEFAULTED               = 0x0002
    SE_DACL_PRESENT                  = 0x0004
    SE_DACL_DEFAULTED                = 0x0008
    SE_SACL_PRESENT                  = 0x0010
    SE_SACL_DEFAULTED                = 0x0020
    SE_DACL_AUTO_INHERIT_REQ         = 0x0100
    SE_SACL_AUTO_INHERIT_REQ         = 0x0200
    SE_DACL_AUTO_INHERITED           = 0x0400
    SE_SACL_AUTO_INHERITED           = 0x0800
    SE_DACL_PROTECTED                = 0x1000
    SE_SACL_PROTECTED                = 0x2000
    SE_SELF_RELATIVE                 = 0x8000


class SecurityDescriptor(object):
    def __init__(self, sd):
        self.raw_sd = sd
        _rev,_sbz,ctrl,owner,group,sacl,dacl = struct.unpack_from("<BBHIIII", sd)
        self.ctrl = ctrl
        self.owner = owner
        self.group = group

        if self.ctrl & SE.SE_SELF_RELATIVE:

            if self.ctrl & SE.SE_SACL_PRESENT:
                self.sacl = sd[sacl:dacl]
            if self.ctrl & SE.SE_DACL_PRESENT:
                self.dacl = sd[dacl:]


class ACL(object):
    def __init__(self, acl):
        _rev,_sbz,_sz,_count,_sbz2 = struct.unpack_from("<BBHHH", acl)


class ACE(object):
    def __init__(self, ace):
        _type,_flags,_size = struct.unpack_from("<BBH", ace)


class ACEType(Enums):
    _enum_ = {
        "AccessAllowed" : 0,
        "AccessDenied" : 1,
        "SystemAudit" : 2,
        "SystemAlarm" : 3,
        "AccessAllowedCompound" : 4,
        "AccessAllowedObject" : 5,
        "AccessDeniedObject" : 6,
        "SystemAuditObject" : 7,
        "SystemAlarmObject" : 8,
        }


class SidTypeName(Enums):
    _enum_ = {
        "User" : 1,
        "Domain" : 2,
        "Alias" : 3,
        "WellKnownGroup" : 4,
        "DeletedAccount" : 5,
        "Invalid" : 6,
        "Unknown" : 7,
        "Computer" : 8,
        }

class ControlFlags(Flags):
    _flags_ = {
        "OwnerDefaulted" : 0x0001,
        "GroupDefaulted" : 0x0002,
        "DACLPresent" : 0x0004,
        "DACLDefaulted" : 0x0008,
        "SACLPresent" : 0x0010,
        "SACLDefaulted" : 0x0020,
        "DACLAutoInheritReq" : 0x0100,
        "SACLAutoInheritReq" : 0x0200,
        "DACLAutoInherited" : 0x0400,
        "SACLAutoInherited" : 0x0800,
        "DACLProtected" : 0x1000,
        "SACLProtected" : 0x2000,
        "SelfRelative" : 0x8000,
        }


class ACEFlags(Flags):
    _flags_ = {
        "ObjectInheritAce" : 0x1,
        "ContainerInheritAce" : 0x2,
        "NoPropagateInheritAce" : 0x4,
        "InheritOnlyAce" : 0x8,
        "InheritedAce" : 0x10,
        "SuccessfulAccessAceFlag" : 0x40,
        "FailedAccessAceFlag" : 0x80,
        }


class ACEObjectFlags(Flags):
    _flags_ = {
        "ObjectTypePresent" : 0x1,
        "InheritedObjectTypePresent" : 0x2,
        }

class AccessMask(Flags):
    _flags_ = {
        "GenericRead":              0x80000000,
        "GenericWrite":             0x40000000,
        "GenericExecute":           0x20000000,
        "GenericAll":               0x10000000,
        "AcessSystemAcl":           0x01000000,
        "Delete":                   0x00010000,
        "ReadControl":              0x00020000,
        "WriteDAC":                 0x00040000,
        "WriteOwner":               0x00080000,
        "Synchronize":              0x00100000,
        "AccessSystemSecurity":     0x01000000,
        "MaximumAllowed":           0x02000000,
        "StandardsRightsRequired":  0x000f0000,
        "StandarRightsAll":         0x001f0000,
        "SpecificRightsAll":        0x0000ffff,
        "ADSRightDSCreateChild":    0x00000001,
        "ADSRightDSDeleteChild":    0x00000002,
        "ADSRightACTRLDSList":      0x00000004,
        "ADSRightDSSelf":           0x00000008,
        "ADSRightDSReadProp":       0x00000010,
        "ADSRightDSWriteProp":      0x00000020,
        "ADSRightDSDeleteTree":     0x00000040,
        "ADSRightDSListObject":     0x00000080,
        "ADSRightDSControlAccess":  0x00000100,
    }

def acl_to_json(acl):
    rev,_sbz,size,count,_sbz2 = struct.unpack_from("<BBHHH", acl)
    ACL = {}
    ACL["Revision"] = rev
    ACL["Size"] = size
    ACL["Count"] = count
    ACL["ACEList"] = ACEList = []
    acestr = acl[8:]
    while count > 0:
        typeraw,flags,size = struct.unpack_from("<BBH", acestr)
        type_ = ACEType(typeraw)
        ACE = {}
        ACE["Type"] = type_.to_json()
        ACE["Flags"] = ACEFlags(flags).to_json()
        ACE["Size"] = size
        amask, = struct.unpack_from("<I", acestr[4:])
        ACE["AccessMask"] = AccessMask(amask).to_json()
        sstr = acestr[8:size]
        if typeraw in [5, 6, 7, 8]:
            objflagsraw, = struct.unpack_from("<I", sstr)
            sstr = sstr[4:]
            objflags = ACEObjectFlags(objflagsraw)
            ACE["ObjectFlags"] = objflags.to_json()
            if objflags.ObjectTypePresent:
                ACE["ObjectType"] = bta.tools.decoding.decode_guid(sstr[:16])
                sstr = sstr[16:]
            if objflags.InheritedObjectTypePresent:
                ACE["InheritedObjectType"] = bta.tools.decoding.decode_guid(sstr[:16])
                sstr = sstr[16:]

        if typeraw in [0, 1, 2, 3, 5, 6, 7, 8]:
            ACE["SID"] = bta.tools.decoding.decode_sid(sstr)

        if type == 0: # ACCESS_ALLOWED
            pass
        elif type == 1: # ACCESS_DENIED
            pass
        elif type == 2: # SYSTEM_AUDIT
            pass
        elif type == 3: # SYSTEM_ALARM
            pass
        elif type == 4: # ACCESS_ALLOWED_COMPOUND
            pass
        elif type == 5: # ACCESS_ALLOWED_OBJECT
            pass
        elif type == 6: # ACCESS_DENIED_OBJECT
            pass
        elif type == 7: # SYSTEM_AUDIT_OBJECT
            pass
        elif type == 8: # SYSTEM_ALARM_OBJECT
            pass

        ACEList.append(ACE)
        acestr = acestr[size:]
        count -= 1
    return ACL


def sd_to_json(sd):
    jsd = {}

    rev,_sbz,rctrl,owner,group,saclofs,daclofs = struct.unpack_from("<BBHIIII", sd)
    ctrl = ControlFlags(rctrl)
    jsd["Revision"] = rev
    jsd["Control"] = ctrl.to_json()
    if ctrl.SelfRelative:
        jsd["Owner"] = bta.tools.decoding.decode_sid(sd[owner:])
        jsd["Group"] = bta.tools.decoding.decode_sid(sd[group:])
        if ctrl.SACLPresent:
            jsd["SACL"] = acl_to_json(sd[saclofs:])
        if ctrl.DACLPresent:
            jsd["DACL"] = acl_to_json(sd[daclofs:])
    return jsd

if __name__ == "__main__":
    from pprint import pprint

    for sd in []:
        pprint(sd_to_json(sd.strip().decode("hex")))
