# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.tools.mtools import Sid, Record

@Miner.register
class ListACE(Miner):
    _name_ = "ListACE"
    _desc_ = "List ACE matching criteria"
    _uses_ = [ "raw.datatable", "raw.sd_table", "raw.guid", "raw.usersid", "special.categories" ]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--type", help="Look only for ACE matching TYPE", metavar="TYPE")
        parser.add_argument("--trustee", help="Look only for ACE of SID", metavar="SID")
        parser.add_argument("--subject", help="Look only for ACE applying to GUID", metavar="GUID")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")

    def type2human(self, objtype):
        if not objtype:
            return objtype
        r = self.guid.find_one({"id":objtype.lower()})
        return r["name"] if r else objtype

    def formatACE(self, truste, subject, accesstype, perm):
        def r(x):
            if type(x) is set:
                if len(x) > 3:
                    return '%d items' % len(x)
                return ', '.join(map(lambda s: unicode(Sid(s, self.datatable)), x))
            return unicode(Sid(x, self.datatable))
        #return (r(truste), r(subject), self.type2human(perm))
        return (r(truste), r(subject), accesstype, self.type2human(perm))

    def summarize_ace(self, trustee, securitydescriptor, aceList):
        perms=[]
        for ace in aceList:
            for perm, val in ace['AccessMask'].items():
                if val:
                    perms.append(perm)
            if 'ObjectType' in ace:
                objtype = self.type2human(ace['ObjectType'])
            else:
                objtype = r"No object type /!\ DANGEROUS"
        return [trustee,
                unicode(Sid(ace['SID'], self.datatable), self.usersid),
                objtype,
                '']

    def getSecurityDescriptor(self, sd_id):
        raw_securitydescriptor = self.sd_table.find_one({'sd_id': sd_id})
        if not raw_securitydescriptor:
            raise Exception('No security descriptor matching {id: %r}' % sd_id)
        return Record(**raw_securitydescriptor)

    def _extractACE(self, sd, l=None):
        if not (sd and sd.sd_value):
            return []
        if not (l in sd.sd_value and 'ACEList' in sd.sd_value[l]):
            return []
        acelist = []
        for ace in sd.sd_value[l]['ACEList']:
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

        desc = []
        if options.subject:
            users = self.datatable.find({'objectSid': options.subject})
            desc.append("Subject=%s" % options.subject)
            info = doc.create_list("Owner")
            table = doc.create_table(desc[0])
            table.add(["Trustee", "Subject", "Acces Type", "Object type"])
            table.add()

            for raw_user in users:
                user = Record(**raw_user)
                securitydescriptor = self.getSecurityDescriptor(user.nTSecurityDescriptor)
                nameowner = self.datatable.find({'objectSid': securitydescriptor.sd_value['Owner']})[0]
                info.add("%s (%s)" % (nameowner["name"] , securitydescriptor.sd_value['Owner']))
                aceList = self.extractACE(securitydescriptor)
                for ace in aceList:
                    if options.type and ace.ObjectType != options.type:
                        continue
                    if options.trustee and ace.SID != options.trustee:
                        continue
                    aceobj = self.formatACE(ace.SID, options.subject, ace.Type, ace.ObjectType)
                    table.add(aceobj)
            table.finished()

        else:
            query = {}
            if options.type:
                query.update({'ObjectType': options.type.lower()})
                desc.append("type=%s" % self.type2human(options.type))
            if options.trustee:
                query.update({'SID': options.trustee.upper()})
                desc.append("trustee=%s" % options.trustee)

            bigquery = {'$or': [
                        {"sd_value.DACL.ACEList": {'$elemMatch': query}},
                        {"sd_value.SACL.ACEList": {'$elemMatch': query}}],
                       }

            desct = ("List ACE where "+ " and ".join(desc)) if desc else "List all ACE"
            table = doc.create_table(desct)
            table.add(["Trustee", "Subjects", "Access Type", "Object type"])
            table.add()

            for raw_sd in self.sd_table.find(bigquery):
                securitydescriptor = Record(**raw_sd)
                query = {
                    'nTSecurityDescriptor': securitydescriptor.sd_id,
                    'objectSid': {'$exists': 1},
                    'objectCategory': {'$in': [self.categories.person, self.categories.group]}
                }
                subjects=set()
                for subject in self.datatable.find(query, {'objectSid': True}):
                    subjects.add(subject['objectSid'])
                if not subjects:
                    continue

                aceList = self.extractACE(securitydescriptor)
                for ace in aceList:
                    if options.type and ace.ObjectType != options.type:
                        continue
                    if options.trustee and ace.SID != options.trustee:
                        continue

                    aceobj = self.formatACE(ace.SID, subjects, ace.Type, ace.ObjectType)
                    table.add(aceobj)

            table.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.sd_table, "sd_id")
        self.assert_field_exists(self.sd_table, "sd_value")
        self.assert_field_type(self.datatable, "rightsGuid", str, unicode)
        self.assert_field_type(self.datatable, "objectSid", str, unicode)
        self.assert_field_type(self.datatable, "nTSecurityDescriptor", int)
        self.assert_field_type(self.datatable, "objectCategory", int)

