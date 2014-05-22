# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner, MinerList


@Miner.register
class AdminSDHolder_Audit(MinerList):
    _name_ = "Audit_SDProp"
    _desc_ = "Run all analyses on Admin SD Holders"
    _report_ = [
        ("SDProp", "--list"),
        ("SDProp", "--orphan"),
        ("SDProp", "--checkACE"),
    ]
