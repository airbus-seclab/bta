# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner, MinerList


@Miner.register
class UAC_Audit(MinerList):
    _name_ = "Audit_UAC"
    _desc_ = "Run all analyses on User Account Control"
    _report_ = [
        ("CheckUAC", "--check", "accountDisable"),
        ("CheckUAC", "--check", "passwdNotrequired"),
        ("CheckUAC", "--check", "passwdCantChange"),
        ("CheckUAC", "--check", "dontExpirePassword"),
    ]
