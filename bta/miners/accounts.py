# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.tools.WellKnownSID import SID2StringFull
from datetime import datetime

@Miner.register
class Accounts(Miner):
    _name_ = "accounts"
    _desc_ = "Look for things on user passwords"
    _uses_ = [ "raw.datatable", "raw.sd_table", "raw.guid" ]

    _types_= ["Person", "Computer"]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--created-since", nargs='?', const=-1, type=int, help="List account created from X days (no argument for listing)")
        parser.add_argument("--changed-since", nargs='?', const=-1, type=int, help="List account changed from X days (no argument for listing)")
        parser.add_argument("--deleted-since", nargs='?', const=-1, type=int, help="List account deleted from X days (no argument for listing)")
        parser.add_argument("--expire-since", nargs='?', const=-1, type=int, help="List account deleted from X days (no argument for listing)")
        parser.add_argument("--owners", nargs='?', const="", type=str, help="List account owners (no argument for listing, regex matching when specified)")
        parser.add_argument("--account-type", nargs='?', const=cls._types_[0], type=str, help="(%s)"%', '.join(cls._types_))
        parser.add_argument("--logon-hours", action="store_true", help="Export accounts that have specific logon hours")
        parser.add_argument("--workstations", action="store_true", help="Export accounts that have workstations restriction")
        parser.add_argument("--operating-systems", action="store_true", help="Export Operating systems, when available")
        parser.add_argument("--script-path", action="store_true", help="Export Script path, when available")


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

    def extract_logon_hours(self, doc):
        accounts = self.datatable.find({"logonHours":{"$exists":1}})
        for acc in accounts:
            t = doc.create_list("The user %s have the following logon hours:"%acc["name"])
            for hour in acc["logonHours"]:
                t.add(hour)
            t.flush()
            t.finished()

    def extract_workstations(self, doc):
        accounts = self.datatable.find({"userWorkstations":{"$exists":1}})
        for acc in accounts:
            t = doc.create_list("The user %s can log on the following workstations:"%acc["name"])
            for workstation in acc["userWorkstations"].split(','):
                t.add(workstation)
            t.flush()
            t.finished()

    def extract_scriptPath(self, doc):
        accounts = self.datatable.find({"scriptPath":{"$exists":1}})
        for acc in accounts:
            t = doc.create_list("The scriptPath of %s is:"%acc["name"])
            t.add(acc["scriptPath"])
            t.flush()
            t.finished()


    def extract_operating_systems(self, doc):
        accounts = self.datatable.find({"operatingSystem":{"$exists":1}})
        u = doc.create_table("Account operating systems")
        u.add(["name","operating system"])
        u.add()
        for acc in accounts:
            u.add([acc["name"],acc["operatingSystem"]])
            u.flush()
        u.finished()

    def run(self, options, doc):
        if options.operating_systems:
            self.extract_operating_systems(doc)

        if options.workstations:
            self.extract_workstations(doc)

        if options.script_path:
            self.extract_scriptPath(doc)

        if options.logon_hours:
            self.extract_logon_hours(doc)

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
