# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
import bson.binary

@Miner.register
class WhoIs(Miner):
    _name_ = "WhoIs"
    _desc_ = "Resolve SID"
    _uses_ = [ "raw.datatable" ]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--sid", help="Look at this SID", metavar="SID")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")

    def run(self, options, doc):
        sec = doc.create_subsection("Who is %s" % options.sid)
        c = self.datatable.find({'objectSid': options.sid})
        for r in c:
            t = sec.create_table("Name=[%s]" % r.get("name",""))
            for k,v in r.iteritems():
                if type(v) is bson.binary.Binary:
                    t.add([k, v.encode('hex')])
                else:
                    t.add([k,v])
            t.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "objectSid")
        self.assert_field_type(self.datatable, "objectSid", str, unicode)
