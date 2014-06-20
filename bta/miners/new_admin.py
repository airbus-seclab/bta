# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.tools.WellKnownSID import SID2StringFull
import datetime

@Miner.register
class NewAdmin(Miner):
    _name_ = "NewAdmin"
    _desc_ = "NewAdmin, list new administrator"
    _uses_ = [ "raw.datatable", "raw.guid", "special.categories" ]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--creation', help='List new administrator since a creation date', metavar='YYYY-MM-DD')

    def newAdmin(self, year, month, day):
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)

        req = {'$and': [
                {"objectCategory" : self.categories.person},
                {"whenCreated": {"$gt": start, "$lt": datetime.datetime.now()}},
                { "$or" :
                    [{ "name": { "$regex": "^adm", "$options": 'i'}},
                    { "name": { "$regex": "^svc-", "$options": 'i'}},]},
                { "userAccountControl": {'$exists': 1}}
            ]}

        for subject in self.datatable.find(req):
            uAcc = subject['userAccountControl']['flags']
            if(uAcc['passwdNotrequired'] or uAcc['dontExpirePassword']):
                result.append([subject['cn'], 'STRANGE', subject['objectSid']])
            else:
                result.append([subject['cn'], ",".join([ a for a,b in subject['userAccountControl']['flags'].items() if b]), SID2StringFull(subject['objectSid'], self.guid)])
        result.insert(0, [])
        result.insert(0, ["cn","accountType","SID"])
        return result

    def run(self, options, doc):
        if(options.creation):
            try:
                date = options.creation.split('-')
                year = int(date[0])
                month = int(date[1])
                day = int(date[2])
            except Exception:
                raise ValueError('Invalid date format "%s" expect YYYY-MM-DD ' % options.creation)
            newAdmin = self.newAdmin(year, month, day)
            t = doc.create_table("Administrator account created after %s-%s-%s" % (year, month, day))
            for disp in newAdmin:
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
