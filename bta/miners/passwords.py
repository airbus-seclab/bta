# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.tools.WellKnownSID import SID2StringFull
from datetime import datetime
import bson.binary

def sane(o):
    if type(o) is bson.binary.Binary:
        return o.encode("hex")
    return unicode(o)


@Miner.register
class Passwords(Miner):
    _name_ = "passwords"
    _desc_ = "Look for things on user passwords"
    _uses_ = [ "raw.datatable", "raw.guid" ]
    _types_= ["Person", "Computer"]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--bad-password-count",action="store_true", help="Find users whose bad password count is non-zero")
        parser.add_argument("--dump-unicode-pwd", action="store_true", help="Dump unicodePwd AD field")
        parser.add_argument("--password-age", nargs='?', const=0, type=int, help="List the password age of all accounts")
        parser.add_argument("--last-logon", nargs='?', const=0, type=int, help="List account unused for X days (No argument for listing)")
        parser.add_argument("--failed-logon", nargs='?', const=0, type=int, help="List failed authentication since X days (No argument for listing)")
        parser.add_argument("--account-creation", action="store_true", help="List all account creation dates")
        parser.add_argument("--never-logged", action="store_true", help="List all account never used")
        parser.add_argument("--account-type", nargs='?', const=cls._types_[0], type=str, help="(%s)"%', '.join(cls._types_))
        parser.add_argument("--pso-details", action="store_true", help="Give details about all Passwords Settings Objects")
        parser.add_argument("--lookingfor-password",  help="Find password strings in 'description' attribute")

    def get_line(self, record, line, flags=None):
        res = [record.get(x,"-") if type(record.get(x,"-")) in [unicode,int,datetime] else unicode(str(record.get(x,"-")), errors='ignore').encode('hex') for x in line]
        if "objectSid" in record:
            res.append(SID2StringFull(record["objectSid"], self.guid))
        else:
            res.append("NOSID:%s" % record['name'])
        if not flags is None:
            if "userAccountControl" in record:
                res.append("%s:%r" % (flags,record["userAccountControl"]["flags"][flags]))
            else:
                res.append("NoAccountControl")

        return res

    def dump_field(self, doc, field):
        t = doc.create_table("Dump of %s for " % (field))
        t.add(["name", field])
        t.add()
        for r in self.datatable.find({field:{"$exists": True}}):
            t.add(self.get_line(r, ["name", field]))
            t.flush()

    def account_creation_date(self, doc, account_type):
        t = doc.create_table("Account creation date")
        t.add(["name", "whenCreated", "comments"])
        t.add()
        for account in self.datatable.find({"whenCreated":{"$exists":True},
                                            "objectCategory":{"$in":[account_type]},
                                            "$or":[{"isDeleted":False}, {"isDeleted":{"$exists":False}}]}):
            t.add(self.get_line(account, ["name", "whenCreated"])+[''])
            t.flush()

    def extract_field_since(self, doc, field, since, account_type):
        results=list()
        for r in self.datatable.find({field:{"$exists": True},"objectCategory":{"$in":[account_type]}}):

            if since < 0:
                cond = (datetime.now()-r[field]).days <= -since
            else:
                cond = (datetime.now()-r[field]).days >= since
            if ( cond or since==0) :
                results.append(self.get_line(r, ["name", field],"accountDisable"))

        t = doc.create_table("Dump of %s for %s" % (field, account_type))
        if len(results)==0:
            t.add(["No Result"])
            return
        else:
            t.add(["name", field, "comments", "userAccountControl"])
            t.add()
            for r in results:
                t.add(r)
        t.flush()

    def never_logged(self, doc, field, account_type):
        t = doc.create_table("Dump of %s" % field)
        t.add(["name","userAccountControl"])
        t.add()
        for account in self.datatable.find({field:{"$exists":False},
                                            "objectCategory":{"$in":[account_type]},
                                            "$or":[{"isDeleted":False}, {"isDeleted":{"$exists":False}}]}):
            x = self.get_line(account, ["name"], "accountDisable")
            t.add(x)
            t.flush()

    def pso_details(self, doc):
        PSObjects_category=self.datatable.find_one({"name":"ms-DS-Password-Settings"},{"DNT_col":True})["DNT_col"]
        PSObjects = self.datatable.find({"objectCategory":PSObjects_category})
        t = doc.create_list("Password Objects details")

        for obj in PSObjects:
            t.add("Display name: %s"%obj["displayName"])
            t.add("Lockout duration: %s"%obj["msDS_LockoutDuration"])
            t.add("Lockout observation Windows: %s"%obj["msDS_LockoutObservationWindow"])
            t.add("Lockout threshold: %s"%obj["msDS_LockoutThreshold"])
            t.add("Maximium password age: %s"%obj["msDS_MaximumPasswordAge"])
            t.add("Minimum password age: %s"%obj["msDS_MinimumPasswordAge"])
            t.add("Minimum password length: %s"%obj["msDS_MinimumPasswordLength"])
            t.add("Password complexity enabled: %s"%obj["msDS_PasswordComplexityEnabled"])
            t.add("Password history length: %s"%obj["msDS_PasswordHistoryLength"])
            t.add("Password setting precedence: %s"%obj["msDS_PasswordSettingsPrecedence"])
            t.flush()
            #t.add(obj["REVERSIBLE"])
            #t.add(obj["APPLIES TO"])

    def lookingfor_password(self, doc, field, strings, account_type):
        t = doc.create_table("Search strings %s in description attribute" % strings)
        t.add(["name","description"])
        t.add()
        for r in self.datatable.find({field:{"$regex": strings }}):
            t.add([r["name"],r["description"]])
            t.flush()

    def run(self, options, doc):
        if options.pso_details:
            self.pso_details(doc)
            return

        if options.account_type not in self._types_:
            account_type=self.datatable.find_one({"name":self._types_[0] })["DNT_col"]
        else:
            account_type=self.datatable.find_one({"name":options.account_type})["DNT_col"]

        if options.bad_password_count:
            self.dump_field(doc, "badPwdCount")

        if options.failed_logon is not None:
            self.extract_field_since(doc, "badPasswordTime", options.failed_logon, account_type)

        if options.password_age is not None:
            arg=options.password_age
            self.extract_field_since(doc, "pwdLastSet", arg, account_type)

        if options.last_logon is not None:
            self.extract_field_since(doc, "lastLogonTimestamp", options.last_logon, account_type)

        if options.account_creation:
            self.account_creation_date(doc, account_type)

        if options.dump_unicode_pwd:
            self.dump_field(doc, "unicodePwd")

        if options.never_logged:
            self.never_logged(doc, "lastLogonTimestamp", account_type)

        if options.lookingfor_password:
            arg=options.lookingfor_password
            self.lookingfor_password(doc, "description", arg, account_type)

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "badPwdCount", int)
        self.assert_field_type(self.datatable, "sAMAccountName", str, unicode)
        self.assert_field_type(self.datatable, "name", str, unicode)
        self.assert_field_type(self.datatable, "description", str, unicode)

