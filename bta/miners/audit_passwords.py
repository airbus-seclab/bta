# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner, MinerList


@Miner.register
class ExtendedRights_Audit(MinerList):
    _name_ = "Audit_Passwords"
    _desc_ = "Run all analyses on passwords"
    _report_ = [
        ("passwords", "--never-logged"),
        ("passwords", "--last-logon", "1215"),
        ("passwords", "--last-logon", "485"),
        ("passwords", "--last-logon", "302"),
        ("passwords", "--bad-password-count"),
    ]

