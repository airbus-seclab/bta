# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner, MinerList


@Miner.register
class Groups_Audit(MinerList):
    _name_ = "Audit_Groups"
    _desc_ = "Run all analyses on groups"
    _report_ = [
        ("ListGroup", "--match", "Domain Admins"),
        ("ListGroup", "--match", "Enterprise Admins"),
    ]
