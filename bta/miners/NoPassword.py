# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
import datetime

@Miner.register
class NewAdmin(Miner):
    _name_ = "Nopassword"
    _desc_ = "Weird paswword policy (No password or password never expire)"
    
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--creation', help='List weird account rights after a creation date', metavar='YYYY-MM-DD')
    
    def findRogue(self, year, month, day):
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)
        req = {'$and': [ {"objectCategory" : self.categories.person},
                         { "userAccountControl": {'$exists': 1}},
                         {'$or': [{'userAccountControl.flags.passwdNotrequired':True},
                                  {'userAccountControl.flags.dontExpirePassword':True}]
                         }]
              }
        
        for subject in self.datatable.find(req):
            result.append([subject['name'], subject['objectSid'], not subject['userAccountControl']['flags']['passwdNotrequired'], not subject['userAccountControl']['flags']['dontExpirePassword']])
        result.insert(0, ["cn","SID", "Required Password", "Password expire"])

        return result
        
    def run(self, options, doc):
        if not options.creation:
            options.creation = "1970-01-01"
        try:
            date = options.creation.split('-')
            year = int(date[0])
            month = int(date[1])
            day = int(date[2])
        except Exception as e:
            raise Exception('Invalid date format "%s" expect YYYY-MM-DD ' % options.creation)
        rogues = self.findRogue(year, month, day)
        t = doc.create_table("Weird accounts account created after %s-%s-%s" % (year, month, day))
        for disp in rogues:
            t.add(disp)
        t.flush()
        t.finished()
        
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "objectCategory")
        self.assert_field_type(self.datatable, "objectCategory", int)
        self.assert_field_exists(self.datatable, "whenCreated")
        self.assert_field_type(self.datatable, "whenCreated", datetime.datetime)
        self.assert_field_type(self.datatable, "name", str, unicode)
        self.assert_field_type(self.datatable, "userAccountControl", dict)
        self.assert_field_type(self.datatable, "cn", str, unicode)
