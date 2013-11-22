# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

import struct
from tools.flags import Flags, Enums

class UserAccountControl(Flags):
    _flags_ = {
        "script":                       0x00000001,
        "accountDisable":               0x00000002,
        "homedirRequired":              0x00000008,
        "lockout":                      0x00000010,
        "passwdNotrequired":            0x00000020,
        "passwdCantChange":             0x00000040,
        "encryptedTextPassAllowed":     0x00000080,
        "tempDuplicateAccount":         0x00000100,
        "normalAccount":                0x00000200,
        "interdomainTrustAccount":      0x00000800,
        "workstationTrustAccount":      0x00001000,
        "serverTrustAccount":           0x00002000,
        "dontExpirePassword":           0x00010000,
        "mnsLogonAccount":              0x00020000,
        "smartcardRequired":            0x00040000,
        "trustedForDelegation":         0x00080000,
        "notDelegated":                 0x00100000,
        "useDESKeyOnly":                0x00200000,
        "dontRequirePreAuth":           0x00400000,
        "passwordExpired":              0x00800000,
        "trustedToAuthForDelegation":   0x01000000,
        "partialSecretsAccount":        0x04000000,
    }

class TrustAttributes(Flags):
    _flags_ = {
        "NON_TRANSITIVE": 0x00000001,
        "UPLEVEL_ONLY": 0x00000002,
        "QUARANTINED_DOMAIN": 0x00000004,
        "FOREST_TRANSITIVE": 0x00000008,
        "CROSS_ORGANIZATION": 0x00000010,
        "WITHIN_FOREST": 0x00000020,
        "TREAT_AS_EXTERNAL": 0x00000040,
        "USES_RC4_ENCRYPTION": 0x00000080,
    }
class TrustType(Enums):
    _enum_ = {
        "DOWNLEVEL": 0x00000001,
        "UPLEVEL": 0x00000002,
        "MIT": 0x00000003,
    }
class TrustDirection(Enums):
    _enum_ = {
        "DISABLED": 0x00000000,
        "INBOUND": 0x00000001,
        "OUTBOUND": 0x00000002,
        "BIDIRECTIONAL": 0x00000003,
    }
