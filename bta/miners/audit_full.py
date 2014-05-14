# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner, MinerList


@Miner.register
class Full_Audit(MinerList):
    _name_ = "Audit_Full"
    _desc_ = "Run all analyses"
    _report_ = [
        "Audit_Groups",
        "Audit_ExtRights",
        "Audit_Passwords",
        "Audit_UAC",
        "Audit_Schema",
        "Audit_SDProp",
    ]
