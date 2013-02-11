from ntds.miners import Miner
from ntds.miners.tools import User, Group, Sid
from pprint import pprint

@Miner.register
class WhoIs(Miner):
    _name_ = "WhoIs"
    _desc_ = "Resolve SID"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--sid", help="Look at this SID", metavar="SID")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")

    def run(self, options):
        dt = options.backend.open_table("datatable")
        pprint(dt.find_one({'objectSid': options.sid}))


