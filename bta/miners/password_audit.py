# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner, MinerList


@Miner.register
class Password_Audit(MinerList):
    _name_ = "PasswordAudit"
    _desc_ = "Run all analyses on passwords"
    _report_ = [
        "info",
        ("passwords", "--dump-unicode-pwd",),
        ("passwords", "--bad-password-count",),
    ]

    
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--key", help="key", metavar="TYPE")

