# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.datatable import UserAccountControl

@Miner.register
class CheckUAC(Miner):
    _name_ = "CheckUAC"
    _desc_ = "Weird paswword policy (No password or password never expire)"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--check', help='List weird user access control Possible values to be checked (comma separated list): %s'%(", ".join(UserAccountControl._flags_.keys())))

    def findRogue(self, flags):
        result = list()
        req = {'$and': [ {'$or':[{"objectCategory" : self.categories.person},
                                 {"objectCategory" : self.categories.computer}]},
                         { "userAccountControl": {'$exists': 1}},
                         {'$and': flags
                         }]
              }

        for subject in self.datatable.find(req):
            result.append([subject['name'], subject['objectSid'], ", ".join([a for a,b in subject['userAccountControl']['flags'].items() if b])])
        result.insert(0, ["cn","SID", "Flags"])

        return result

    def run(self, options, doc):
        flags=list()
        try:
            for f in options.check.split(","):
                if f in UserAccountControl._flags_.keys():
                    flags.append({"userAccountControl.flags.%s"%f:True})

        except:
            print 'Invalid \'check\' argument: %s\nUse $btaminer %s -h for more information'%(options.check if options.check else "", self._name_)
            exit(1)

        rogues = self.findRogue(flags)
        t = doc.create_table("Weird account rights with all flags:%s"%options.check)
        for disp in rogues:
            t.add(disp)
        t.flush()
        t.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "name", str, unicode)
        self.assert_field_type(self.datatable, "userAccountControl", dict)
        self.assert_field_type(self.datatable, "cn", str, unicode)
