from ntds.miners import Miner
from ntds.miners.tools import User, Group, Sid, Record
import re


CATEGORY_GROUP = 5945
CATEGORY_USER  = 3818

@Miner.register
class ListACE(Miner):
    _name_ = "ListACE"
    _desc_ = "List ACE matching criteria"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--type", help="Look only for ACE matching TYPE", metavar="TYPE")
        parser.add_argument("--trustee", help="Look only for ACE of SID", metavar="SID")
        parser.add_argument("--subject", help="Look only for ACE applying to GUID", metavar="GUID")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")

    def type2human(self, objtype):
        r = self.dt.find_one({"rightsGuid":objtype.lower()})
        return r["name"] if r else objtype

    def summarize_ace(self, trustee, securitydescriptor, aceList):
        perms=[]
        for ace in aceList:
            for perm, val in ace['AccessMask'].items():
                if val:
                    perms.append(perm)
            if 'ObjectType' in ace:
                objtype = self.type2human(ace['ObjectType'])
            else:
                objtype = "No object type /!\ DANGEROUS"
        return [#str(Sid(self.dt, verbose=self.options.verbose, objectSid=trustee)),
                trustee,
                str(Sid(self.dt, verbose=self.options.verbose, objectSid=ace['SID'])),
                objtype,
                '']
                #', '.join(perms)]

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
        desc = []
        queries = []
        if options.subject:
            users = dt.find({'objectSid': options.subject})
            desc.append("trustee=%s" % options.subject)

            for raw_user in users:
                user = Record(**raw_user)
                securitydescriptor = self.getSecurityDescriptor(user.nTSecurityDescriptor)
                aceList = self.extractACE(securitydescriptor)
                filteredACE = []
                for ace in aceList:
                    if options.type and ace.ObjectType != options.type:
                        continue
                    if options.trustee and ace.SID != options.trustee:
                        continue
                    filteredACE.append(ace)
                res.append((user, securitydescriptor, filteredACE))
        else:
            query = {}
            if options.type:
                query.update({'ObjectType': options.type.lower()})
                desc.append("type=%s" % options.type)
            if options.trustee:
                query.update({'SID': options.trustee.upper()})
                desc.append("trustee=%s" % options.trustee)

            bigquery = {'$or': [
                        {"value.DACL.ACEList": {'$elemMatch': query}},
                        {"value.SACL.ACEList": {'$elemMatch': query}}],
                       }

            desct = ("List ACE where "+ " and ".join(desc)) if desc else "List all ACE"
            table = doc.create_table(desct)
            table.add(["Trustee", "Subject", "Object type", "Perms"])
            table.add()

            entry = 0
            for raw_sd in sdt.find(bigquery):
                securitydescriptor = Record(**raw_sd)
                aceList = self.extractACE(securitydescriptor)
                filteredACE = filter(lambda x: x.ObjectType == options.type, aceList)
                trustees = set(map(lambda x: x['SID'], filteredACE))
                users = dt.find({'nTSecurityDescriptor': securitydescriptor.id})
                for user in users:
                    cat = int(user.get('objectCategory', 0))
                    if cat not in [CATEGORY_USER, CATEGORY_GROUP]:
                        continue
                    entry += 1
                    #trustees = map(lambda x:  str(Sid(self.dt, verbose=self.options.verbose, objectSid=x)), trustees)
                    table.add([', '.join(trustees),
                              str(Sid(self.dt, verbose=self.options.verbose, objectSid=user['objectSid'])),
                              None, None])
            table.finished()
