# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
from collections import defaultdict
from bta.tools.WellKnownSID import SID2StringFull
from datetime import datetime

@Miner.register
class Passwords(Miner):
    _name_ = "accounts"
    _desc_ = "Look for things on user passwords"
    _types_= ["Person", "Computer"]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--created-since", nargs='?', const=-1, type=int, help="List account created from X days (no argument for listing)")
        parser.add_argument("--changed-since", nargs='?', const=-1, type=int, help="List account changed from X days (no argument for listing)")
        parser.add_argument("--deleted-since", nargs='?', const=-1, type=int, help="List account deleted from X days (no argument for listing)")
        parser.add_argument("--expire-since", nargs='?', const=-1, type=int, help="List account deleted from X days (no argument for listing)")
        parser.add_argument("--owners", nargs='?', const="", type=str, help="List account owners (no argument for listing, regex matching when specified)")
        parser.add_argument("--account-type", nargs='?', const=cls._types_[0], type=str, help="(%s)"%', '.join(cls._types_))

    
    def get_line(self, record, line):
    	res = [record.get(x,"-") if type(record.get(x,"-")) in [unicode,int,datetime] else unicode(str(record.get(x,"-")), errors='ignore').encode('hex') for x in line]
        res.append(SID2StringFull(record["objectSid"], self.guid))
        return res

    def extract_field_since(self, doc, field, since, types):
        results=list()
        for r in self.datatable.find({field:{"$exists": True},"objectCategory":{"$in":types}}):
            if ( (datetime.now()-r[field]).days >= since or since<0):
                results.append(self.get_line(r, ["name", field]))

        t = doc.create_table("Dump of %s" % field)

        if len(results) == 0:
            t.add(["No Result"])
            return
        else:
            t.add(["name", field, "comments"])
            t.add()
            for r in results:
                t.add(r)
                t.flush()

    def extract_replPropertyMetaData(self, node, OID):
        for r in node.get("replPropertyMetaData", list()):
            if r["OID"] == OID:
                return r
        return list()

    def extract_advanced_field_since(self, doc, field, since, types):
        results = list()
        for r in self.datatable.find({"replPropertyMetaData.OID": field, "objectCategory": {"$in": types}}):
            the_date = self.extract_replPropertyMetaData(r, field)["date"]
            if (datetime.now() - the_date).days >= since or since < 0:
                results.append([r["name"], the_date, SID2StringFull(r["objectSid"], self.guid)])

        t = doc.create_table("Dump of %s" % field)

        if len(results) == 0:
            t.add(["No Result"])
            return
        else:
            t.add(["name", field, "comments"])
            t.add()
            for r in results:
                t.add(r)

    def extract_owner(self, doc, account, types):
        t = doc.create_table("Dump of accounts %s owners" % account)
        t.add(["account", "owner"])
        t.add()
        req = {"objectCategory": {"$in": types}}
        if account != "":
            req.update({"name": {"$regex": account, "$options": "-i"}})
        for r in self.datatable.find(req, {"nTSecurityDescriptor": 1, "objectSid": 1}):
            infos = self.sd_table.find_one({"sd_id": r["nTSecurityDescriptor"]}, {"sd_value.Owner": 1})
            t.add([SID2StringFull(r["objectSid"], self.guid), SID2StringFull(infos["sd_value"]["Owner"], self.guid)])
        t.flush()

    def run(self, options, doc):

        if options.account_type not in self._types_:
            account_type = self.datatable.find_one({"name": self._types_[0] })["DNT_col"]
        else:
            account_type = self.datatable.find_one({"name": options.account_type})["DNT_col"]

        if options.created_since is not None:
            self.extract_field_since(doc, "whenCreated", options.created_since, [account_type])
    
        if options.changed_since is not None:
            self.extract_field_since(doc, "whenChanged", options.created_since, [account_type])

        if options.expire_since is not None:
            self.extract_field_since(doc, "accountExpires", options.created_since, [account_type])

        if options.owners is not None:
            self.extract_owner(doc, options.owners, [account_type])

        if options.deleted_since is not None:
            self.extract_advanced_field_since(doc, "1.2.840.113556.1.2.48", options.deleted_since, [account_type])

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "name", str, unicode)
