from ntds.miners import Miner
from ntds.miners.tools import User, Group, Sid
import re

@Miner.register
class ListGroup(Miner):
    _name_ = "ListACE"
    _desc_ = "List ACE matching criteria"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--type", help="Look only for ACE matching TYPE", metavar="TYPE")
        parser.add_argument("--owner", help="Look only for ACE owned by SID", metavar="SID")
        parser.add_argument("--target", help="Look only for ACE applying to GUID", metavar="GUID")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")

    def summarize_ace(self, acl, ace):
        s='Owner={0[Owner]:40} Object={1[SID]:60}'.format(acl['value'], ace)
        perms=[]
        for perm, val in ace['AccessMask'].items():
            if val:
                perms.append(perm)
        s = s + ' ' + ', '.join(perms)
        return s

    def run(self, options):
        dt = options.backend.open_table("datatable")
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

