# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner, MinerList


@Miner.register
class Schema_Audit(MinerList):
    _name_ = "Audit_Schema"
    _desc_ = "Run all analyses on schemas"
    _report_ = [
        ("Schema", "--timelineAS", "created"),
        ("Schema", "--timelineAS", "changed"),
        ("Schema", "--timelineCS", "created"),
        ("Schema", "--timelineCS", "changed"),
        ("Schema", "--owner"),
    ]
