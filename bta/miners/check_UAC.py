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
        parser.add_argument('--check', help='List weird user access control Possible values to be checked (comma separated list): %s'%(", ".join(UserAccountControl._flags_.keys())))

    def findRogue(self, flags):
        req =  (((Field("objectCategory") == self.categories.person) 
                 | (Field("objectCategory") == self.categories.computer))
                & (Field("userAccountControl") != None))
        for f in flags:
            req &= Field(f) == True

        result = [["cn","SID", "Flags"]]
        for subject in self.datasd.find(req):
            result.append([subject['name'], subject['objectSid'], ", ".join([a for a,b in subject['userAccountControl']['flags'].items() if b])])
        return result

    def run(self, options, doc):
        flags=list()
        try:
            for f in options.check.split(","):
                if f in UserAccountControl._flags_.keys():
                    flags.append("userAccountControl.flags.%s"%f)

        except:
            print 'Invalid \'check\' argument: %s\nUse $btaminer %s -h for more information'%(options.check if options.check else "", self._name_)
            exit(1)

        rogues = self.findRogue(flags)
        t = doc.create_table("Weird account rights with all flags:%s"%options.check)
        for disp in rogues:
            t.add(disp)
        t.flush()
        t.finished()

