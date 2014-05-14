# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

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
