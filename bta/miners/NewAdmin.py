from bta.miners import Miner
import datetime

@Miner.register
class NewAdmin(Miner):
    _name_ = "NewAdmin"
    _desc_ = "NewAdmin, list new administrator"
    
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--creation', help='List new administrator since a creation date', metavar='YYYY-MM-DD')
    
    def newAdmin(self, year, month, day):
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)
        
        req = {'$and': [
                {"objectCategory" : str(self.categories.person)},
                {"whenCreated": {"$gt": start, "$lt": datetime.datetime.now()}},
                { "$or" : 
                    [{ "name": { "$regex": "^adm", "$options": 'i'}}, 
                    { "name": { "$regex": "^svc-", "$options": 'i'}},]},
                { "userAccountControl": {'$exists': 1}}
            ]}
        
        for subject in self.dt.find(req):
            uAcc = int(subject['userAccountControl'])
            npwdreq = uAcc&0x20
            pwdnoexp = uAcc&0x10000
            if(npwdreq or pwdnoexp):
                result.append([subject['cn'], 'STRANGE', subject['objectSid']])
            else:
                result.append([subject['cn'], subject['userAccountControl'], subject['objectSid']])
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
            except Exception as e:
                raise Exception('Invalid date format "%s" expect YYYY-MM-DD ' % options.creation)
            newAdmin = self.newAdmin(year, month, day)
            t = doc.create_table("Administrator account created after %s-%s-%s" % (year, month, day))
            for disp in newAdmin:
                t.add(disp)
            t.flush()
            t.finished()
        
