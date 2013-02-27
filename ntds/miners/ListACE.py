from ntds.miners import Miner
from ntds.miners.tools import User, Group, Sid, Record
import re


@Miner.register
class ListACE(Miner):
    _name_ = "ListACE"
    _desc_ = "List ACE matching criteria"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--type", help="Look only for ACE matching TYPE", metavar="TYPE")
        parser.add_argument("--user", help="Look only for ACE of SID", metavar="SID")
        parser.add_argument("--target", help="Look only for ACE applying to GUID", metavar="GUID")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")

    def type2human(self, objtype):
        r = self.dt.find_one({"rightsGuid":objtype.lower()})
        return r["name"] if r else objtype

    def summarize_ace(self, acl, ace):
        perms=[]
        for perm, val in ace['AccessMask'].items():
            if val:
                perms.append(perm)
        if 'ObjectType' in ace:
            objtype = self.type2human(ace['ObjectType'])
        else:
            objtype = "No object type /!\ DANGEROUS"

    def getSecurityDescriptor(self, sd_id):
        raw_securitydescriptor = self.sd.find_one({'id': sd_id})
        if not raw_securitydescriptor:
            raise Exception('No security descriptor matching {id: %r}' % sd_id)
        return Record(**raw_securitydescriptor)

    def _extractACE(self, sd, l=None):
        if not (sd and sd.value):
            return []
        if not (l in sd.value and 'ACEList' in sd.value[l]):
            return []
        acelist = []
        for ace in sd.value[l]['ACEList']:
            acelist.append(Record(**ace))
        return acelist

    def extractACE(self, sd):
        return self._extractACE(sd, l='DACL') + self._extractACE(sd, l='SACL')

    def show(self, user, securitydescriptor, ace):
        perms=[]
        for perm, val in ace['AccessMask'].items():
            if val:
                perms.append(perm)
        return '{0[cn]} on {2[SID]}: {3}'.format(user, securitydescriptor, ace, ', '.join(perms))

    def run(self, options, doc):
        self.options = options
        self.dt = dt = options.backend.open_table("datatable")
        self.sd = sdt = options.backend.open_table("sdtable")

        res = []
        queries = []
        if options.user:
            users = dt.find({'objectSid': options.user})

            for raw_user in users:
                user = Record(**raw_user)
                securitydescriptor = self.getSecurityDescriptor(user.nTSecurityDescriptor)
                aceList = self.extractACE(securitydescriptor)
                for ace in aceList:
                    if options.type and ace.ObjectType != options.type:
                        continue
                    if options.target and ace.SID != options.target:
                        continue
                    res.append((user, securitydescriptor, ace))
        else:
            if options.type:
                query = {'$or': [
                            {"value.DACL.ACEList": {'$elemMatch': {'ObjectType': re.compile(options.type, re.IGNORECASE )}}},
                            {"value.SACL.ACEList": {'$elemMatch': {'ObjectType': re.compile(options.type, re.IGNORECASE )}}}, ]}
                queries.append(query)
            if options.target:
                query = {'$or': [
                            {"value.DACL.ACEList": {'$elemMatch': {'SID': re.compile(options.target, re.IGNORECASE )}}},
                            {"value.SACL.ACEList": {'$elemMatch': {'SID': re.compile(options.target, re.IGNORECASE )}}}, ]}
                queries.append(query)
            bigquery = {'$and': queries}

            for raw_sd in sdt.find(bigquery):
                securitydescriptor = Record(**raw_sd)
                aceList = self.extractACE(securitydescriptor)
                users = dt.find({'nTSecurityDescriptor': securitydescriptor.id})
                for user in users:
                    res.append((user, securitydescriptor, ace))
        for t in res:
            user, securitydescriptor, ace = t
            print self.show(*t)
