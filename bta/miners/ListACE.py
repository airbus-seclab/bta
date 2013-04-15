from bta.miners import Miner
from bta.miners.tools import User, Group, Sid, Record
import re

p2h={'00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password',
 '014bf69c-7b3b-11d1-85f6-08002be74fab': 'Change-Domain-Master',
 '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5': 'Enable-Per-User-Reversibly-Encrypted-Password',
 '06bd3200-df3e-11d1-9c86-006008764d0e': 'msmq-Receive',
 '06bd3201-df3e-11d1-9c86-006008764d0e': 'msmq-Peek',
 '06bd3202-df3e-11d1-9c86-006008764d0e': 'msmq-Send',
 '06bd3203-df3e-11d1-9c86-006008764d0e': 'msmq-Receive-journal',
 '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd': 'Recalculate-Hierarchy',
 '0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Certificate-Enrollment',
 '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes',
 '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Synchronize',
 '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Manage-Topology',
 '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All',
 '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2': 'Read-Only-Replication-Secret-Synchronization',
 '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8': 'Reload-SSL-Certificate',
 '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd': 'Allocate-Rids',
 '280f369c-67c7-438e-ae98-1d46f3c6f541': 'Update-Password-Not-Required-Bit',
 '2f16c4a5-b98e-432c-952a-cb388ba33f2e': 'DS-Execute-Intentions-Script',
 '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e': 'DS-Clone-Domain-Controller',
 '440820ad-65b4-11d1-a3da-0000f875ae0d': 'Add-GUID',
 '45ec5156-db7e-47bb-b53f-dbeb2d03c40f': 'Reanimate-Tombstones',
 '4b6e08c0-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-Dead-Letter',
 '4b6e08c1-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-Dead-Letter',
 '4b6e08c2-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-computer-Journal',
 '4b6e08c3-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-computer-Journal',
 '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc': 'DS-Query-Self-Quota',
 '62dd28a8-7f46-11d2-b9ad-00c04f79f805': 'Recalculate-Security-Inheritance',
 '68b1d179-0d15-4d4f-ab71-46152e79a7bc': 'Allowed-To-Authenticate',
 '69ae6200-7f46-11d2-b9ad-00c04f79f805': 'DS-Check-Stale-Phantoms',
 '7726b9d5-a4b4-4288-a6b2-dce952e80a7f': 'Run-Protect_Admin_Groups-Task',
 '7c0e2a7c-a419-48e4-a995-10180aad54dd': 'Manage-Optional-Features',
 '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set',
 '91d67418-0135-4acc-8d79-c08e857cfbec': 'SAM-Enumerate-Entire-Domain',
 '9432c620-033c-4db7-8b58-14ef6d0bf477': 'Refresh-Group-Cache',
 '9923a32a-3607-11d2-b9be-0000f87a36b2': 'DS-Install-Replica',
 'a05b8cc2-17bc-4802-a710-e7c15ab866a2': 'Certificate-AutoEnrollment',
 'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open-Address-Book',
 'ab721a52-1e2f-11d0-9819-00aa0040529b': 'Domain-Administer-Server',
 'ab721a53-1e2f-11d0-9819-00aa0040529b': 'User-Change-Password',
 'ab721a54-1e2f-11d0-9819-00aa0040529b': 'Send-As',
 'ab721a56-1e2f-11d0-9819-00aa0040529b': 'Receive-As',
 'b4e60130-df3f-11d1-9c86-006008764d0e': 'msmq-Open-Connector',
 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Planning',
 'b7b1b3de-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Logging',
 'ba33815a-4f93-4c76-87f3-57574bff8109': 'Migrate-SID-History',
 'bae50096-4752-11d1-9052-00c04fc2d4cf': 'Change-PDC',
 'be2bb760-7f46-11d2-b9ad-00c04f79f805': 'Update-Schema-Cache',
 'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd': 'Change-Infrastructure-Master',
 'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501': 'Unexpire-Password',
 'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd': 'Change-Rid-Master',
 'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd': 'Change-Schema-Master',
 'e2a36dc9-ae17-47c3-b58b-be34c55ba633': 'Create-Inbound-Forest-Trust',
 'edacfd8f-ffb3-11d1-b41d-00a0c968f939': 'Apply-Group-Policy',
 'ee914b82-0a98-11d1-adbb-00c04fd8d5cd': 'Abandon-Replication',
 'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96': 'DS-Replication-Monitor-Topology',
 'fec364e0-0a98-11d1-adbb-00c04fd8d5cd': 'Do-Garbage-Collection'}



class AccessControlEntry(object):
    def __init__(self, trustee=None, subject=None, perm=None):
        self.trustee = trustee
        self.subject = subject
        self.perm    = perm
    def get_tuple(self):
        def r(x):
            if type(x) is set:
                if len(x) > 3:
                    return '%d items' % len(x)
                return ', '.join(x)
            return x
        return (r(self.trustee), r(self.subject),  r(p2h.get(self.perm, self.perm)))


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
        r = self.datatable.find_one({"rightsGuid":objtype.lower()})
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
        return [#str(Sid(self.datatable, verbose=self.options.verbose, objectSid=trustee)),
                trustee,
                str(Sid(self.datatable, verbose=self.options.verbose, objectSid=ace['SID'])),
                objtype,
                '']
                #', '.join(perms)]

    def getSecurityDescriptor(self, sd_id):
        raw_securitydescriptor = self.sd_table.find_one({'id': sd_id})
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

        res = []
        desc = []
        queries = []
        if options.subject:
            users = self.datatable.find({'objectSid': options.subject})
            desc.append("trustee=%s" % options.subject)

            table = doc.create_table(desc)
            table.add(["Trustee", "Subject", "Object type"])
            table.add()

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
                    aceobj = AccessControlEntry(trustee=ace.SID, subject=options.subject, perm=ace.ObjectType)
                    table.add(aceobj.get_tuple())
            table.finished()
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
            table.add(["Subject", "Trustee", "Object type"])
            table.add()

            for raw_sd in self.sd_table.find(bigquery):
                securitydescriptor = Record(**raw_sd)
                query = {
                    'nTSecurityDescriptor': securitydescriptor.id,
                    'objectSid': {'$exists': 1},
                    'objectCategory': {'$in': [str(self.categories.person), str(self.categories.group)]} 
                }
                subjects=set()
                for subject in self.datatable.find(query, {'objectSid': True}):
                    subjects.add(subject['objectSid'])
                if not subjects:
                    continue
    
                aceList = self.extractACE(securitydescriptor)
                for ace in aceList:
                    if options.type and ace.ObjectType != options.type: continue
                    if options.trustee and ace.SID != options.trustee: continue

                    aceobj = AccessControlEntry(trustee=ace.SID, subject=subjects,
                                                perm=ace.ObjectType)
                    table.add(aceobj.get_tuple())

            table.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.sd_table, "id")
        self.assert_field_type(self.datatable, "rightsGuid", str, unicode)
        self.assert_field_type(self.datatable, "objectSid", str, unicode)
        self.assert_field_type(self.datatable, "nTSecurityDescriptor", int)
        self.assert_field_type(self.datatable, "objectCategory", str, unicode)

