# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner, MinerList


@Miner.register
class ExtendedRights_Audit(MinerList):
    _name_ = "Audit_ExtRights"
    _desc_ = "Run all analyses on extended rights"
    _report_ = [
        ("ListACE", "--type", "00299570-246d-11d0-a768-00aa006e0529"),
        ("ListACE", "--type", "ab721a54-1e2f-11d0-9819-00aa0040529b"),
        ("ListACE", "--type", "bf9679c0-0de6-11d0-a285-00aa003049e2"),
    ]
