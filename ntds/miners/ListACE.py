from ntds.miners import Miner
from ntds.miners.tools import User, Group, Sid
import re


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


        return [str(Sid(self.dt, verbose=self.options.verbose, objectSid=acl['value']['Owner'])),
                str(Sid(self.dt, verbose=self.options.verbose, objectSid=ace['SID'])),
                objtype,
                ', '.join(perms)]

    def run(self, options, doc):
        self.options = options
        self.dt = dt = options.backend.open_table("datatable")
        sdt = options.backend.open_table("sdtable")
        
        desc = []
        queries = []
        if options.owner:
            queries.append({'value.Owner': options.owner})
            desc.append("owner=%s" % options.owner)
        if options.type:
            desc.append("type=%s" % options.type)
            query = {'$or': [
                        {"value.DACL.ACEList": {'$elemMatch': {'ObjectType': re.compile(options.type, re.IGNORECASE )}}},
                        {"value.SACL.ACEList": {'$elemMatch': {'ObjectType': re.compile(options.type, re.IGNORECASE )}}}, ]}
            queries.append(query)
        if options.target:
            desc.append("target=%s" % options.target)
            query = {'$or': [
                        {"value.DACL.ACEList": {'$elemMatch': {'SID': re.compile(options.target, re.IGNORECASE )}}},
                        {"value.SACL.ACEList": {'$elemMatch': {'SID': re.compile(options.target, re.IGNORECASE )}}}, ]}
            queries.append(query)
        bigquery = {'$and': queries} if queries else {"value":{"$ne":None}}

        desct = ("List ACE where "+ " and ".join(desc)) if desc else "List all ACE"
        table = doc.create_table(desct)
        table.add(["Owner", "Object", "Object type", "Perms"])
        table.add()

        for acl in sdt.find(bigquery):
            for listName in ['DACL', 'SASL']:
                if listName not in acl['value']:
                    continue
                for ace in acl['value'][listName]['ACEList']:
                    if options.type and 'objectType' in ace and ace['objectType'] != options.type:
                        continue
                    if options.target and ace['SID'] != options.target:
                        continue
                    table.add(self.summarize_ace(acl, ace))
        table.finished()
