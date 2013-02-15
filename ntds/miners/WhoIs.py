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

    def run(self, options, doc):
        dt = options.backend.open_table("datatable")
        sec = doc.create_subsection("Who is %s" % options.sid)
        
        c = dt.find({'objectSid': options.sid})
        for r in c:
            t = sec.create_table("Name=[%s]" % r.get("name",""))
            for k,v in r.iteritems():
                t.add([k,v])
            t.finished()

