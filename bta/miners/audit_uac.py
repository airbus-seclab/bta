# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner, MinerList


@Miner.register
class UAC_Audit(MinerList):
    _name_ = "Audit_UAC"
    _desc_ = "Run all analyses on User Account Control"
    _report_ = [
        ("CheckUAC", "accountDisable"),
        ("CheckUAC", "passwdNotrequired"),
        ("CheckUAC", "passwdCantChange"),
        ("CheckUAC", "dontExpirePassword"),
    ]
