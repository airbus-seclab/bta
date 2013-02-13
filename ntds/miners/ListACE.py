from ntds.miners import Miner
from ntds.miners.tools import User, Group, Sid
import re

perms2human={'06bd3202-df3e-11d1-9c86-006008764d0e': 'msmq-Send', 'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd': 'Change-Infrastructure-Master', '4b6e08c1-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-Dead-Letter', 'b7b1b3de-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Logging', '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Synchronize', '68b1d179-0d15-4d4f-ab71-46152e79a7bc': 'Allowed-To-Authenticate', '69ae6200-7f46-11d2-b9ad-00c04f79f805': 'DS-Check-Stale-Phantoms', '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc': 'DS-Query-Self-Quota', 'b7b1b3dd-ab09-4242-9e30-9980e5d322f7': 'Generate-RSoP-Planning', 'bae50096-4752-11d1-9052-00c04fc2d4cf': 'Change-PDC', '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd': 'Allocate-Rids', '62dd28a8-7f46-11d2-b9ad-00c04f79f805': 'Recalculate-Security-Inheritance', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes-All', '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2': 'Read-Only-Replication-Secret-Synchronization', '45ec5156-db7e-47bb-b53f-dbeb2d03c40f': 'Reanimate-Tombstones', '440820ad-65b4-11d1-a3da-0000f875ae0d': 'Add-GUID', '2f16c4a5-b98e-432c-952a-cb388ba33f2e': 'DS-Execute-Intentions-Script', 'a1990816-4298-11d1-ade2-00c04fd8d5cd': 'Open-Address-Book', '00299570-246d-11d0-a768-00aa006e0529': 'User-Force-Change-Password', '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8': 'Reload-SSL-Certificate', 'edacfd8f-ffb3-11d1-b41d-00a0c968f939': 'Apply-Group-Policy', '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e': 'DS-Clone-Domain-Controller', '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5': 'Enable-Per-User-Reversibly-Encrypted-Password', 'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501': 'Unexpire-Password', '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Get-Changes', '4b6e08c0-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-Dead-Letter', 'ab721a54-1e2f-11d0-9819-00aa0040529b': 'Send-As', '06bd3203-df3e-11d1-9c86-006008764d0e': 'msmq-Receive-journal', '06bd3200-df3e-11d1-9c86-006008764d0e': 'msmq-Receive', 'ab721a53-1e2f-11d0-9819-00aa0040529b': 'User-Change-Password', '7726b9d5-a4b4-4288-a6b2-dce952e80a7f': 'Run-Protect_Admin_Groups-Task', '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2': 'DS-Replication-Manage-Topology', 'b4e60130-df3f-11d1-9c86-006008764d0e': 'msmq-Open-Connector', 'e2a36dc9-ae17-47c3-b58b-be34c55ba633': 'Create-Inbound-Forest-Trust', 'fec364e0-0a98-11d1-adbb-00c04fd8d5cd': 'Do-Garbage-Collection', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2': 'Certificate-AutoEnrollment', 'be2bb760-7f46-11d2-b9ad-00c04f79f805': 'Update-Schema-Cache', '0e10c968-78fb-11d2-90d4-00c04f79dc55': 'Certificate-Enrollment', '7c0e2a7c-a419-48e4-a995-10180aad54dd': 'Manage-Optional-Features', 'ba33815a-4f93-4c76-87f3-57574bff8109': 'Migrate-SID-History', 'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd': 'Change-Rid-Master', 'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96': 'DS-Replication-Monitor-Topology', '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd': 'Recalculate-Hierarchy', '014bf69c-7b3b-11d1-85f6-08002be74fab': 'Change-Domain-Master', '280f369c-67c7-438e-ae98-1d46f3c6f541': 'Update-Password-Not-Required-Bit', '91d67418-0135-4acc-8d79-c08e857cfbec': 'SAM-Enumerate-Entire-Domain', '9432c620-033c-4db7-8b58-14ef6d0bf477': 'Refresh-Group-Cache', 'ab721a55-1e2f-11d0-9819-00aa0040529b': 'Send-To', '9923a32a-3607-11d2-b9be-0000f87a36b2': 'DS-Install-Replica', '89e95b76-444d-4c62-991a-0facbeda640c': 'DS-Replication-Get-Changes-In-Filtered-Set', 'ab721a56-1e2f-11d0-9819-00aa0040529b': 'Receive-As', '4b6e08c3-df3c-11d1-9c86-006008764d0e': 'msmq-Peek-computer-Journal', 'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd': 'Change-Schema-Master', 'ab721a52-1e2f-11d0-9819-00aa0040529b': 'Domain-Administer-Server', 'ee914b82-0a98-11d1-adbb-00c04fd8d5cd': 'Abandon-Replication', '06bd3201-df3e-11d1-9c86-006008764d0e': 'msmq-Peek', '4b6e08c2-df3c-11d1-9c86-006008764d0e': 'msmq-Receive-computer-Journal'}

human2perms=dict(map(lambda x: (x[1],x[0]), perms2human.items()))


@Miner.register
class ListACE(Miner):
    _name_ = "ListACE"
    _desc_ = "List ACE matching criteria"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--type", help="Look only for ACE matching TYPE", metavar="TYPE")
        parser.add_argument("--owner", help="Look only for ACE owned by SID", metavar="SID")
        parser.add_argument("--target", help="Look only for ACE applying to GUID", metavar="GUID")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")


    def type2human(self, objtype):
        return perms2human.get(objtype.lower(), objtype)

    def summarize_ace(self, acl, ace):
        s='Owner={0:40} Object={1:60}'.format(Sid(self.dt, verbose=self.options.verbose, objectSid=acl['value']['Owner']),
                                                Sid(self.dt, verbose=self.options.verbose, objectSid=ace['SID']))
        perms=[]
        for perm, val in ace['AccessMask'].items():
            if val:
                perms.append(perm)
        if 'ObjectType' in ace:
            objtype = ' ObjectType=%s ' % (self.type2human(ace['ObjectType']))
        else:
            objtype = " No object type /!\ DANGEROUS "
        s = s + objtype + ', '.join(perms)
        return s

    def run(self, options):
        self.options = options
        self.dt = dt = options.backend.open_table("datatable")
        sdt = options.backend.open_table("sdtable")

        queries = []
        if options.owner:
            queries.append({'value.Owner': options.owner})
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

        for acl in sdt.find(bigquery):
            for listName in ['DACL', 'SASL']:
                if listName not in acl['value']:
                    continue
                for ace in acl['value'][listName]['ACEList']:
                    if options.type and 'objectType' in ace and ace['objectType'] != options.type:
                        continue
                    if options.target and ace['SID'] != options.target:
                        continue
                    print self.summarize_ace(acl, ace)

