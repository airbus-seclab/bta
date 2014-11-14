# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.datatable import UserAccountControl
from bta.tools.expr import Field

@Miner.register
class CheckUAC(Miner):
    _name_ = "CheckUAC"
    _desc_ = "Weird paswword policy (No password or password never expire)"
    _uses_ = [ "virtual.datasd", "special.categories" ]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('flags', help='List weird user access control', nargs="*", choices=UserAccountControl._flags_.keys()+[[]])

    def findRogue(self, flags):
        req =  (((Field("objectCategory") == self.categories.person) 
                 | (Field("objectCategory") == self.categories.computer))
                & (Field("userAccountControl").present()))
        for f in flags:
            req &= Field("userAccountControl").flag_on(f)

        result = [["cn","SID", "Flags"],[]]
        for subject in self.datasd.find(req):
            result.append([subject['name'], subject['objectSid'], ", ".join([a for a,b in subject['userAccountControl']['flags'].items() if b])])
        return result

    def run(self, options, doc):

        rogues = self.findRogue(options.flags)
        t = doc.create_table("Weird account rights with all flags: %s"% ", ".join(options.flags))
        for disp in rogues:
            t.add(disp)
        t.flush()
        t.finished()

