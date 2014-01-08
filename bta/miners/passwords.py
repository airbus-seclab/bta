# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
from collections import defaultdict
from bta.tools.WellKnownSID import SID2StringFull
from datetime import datetime

@Miner.register
class Passwords(Miner):
    _name_ = "passwords"
    _desc_ = "Look for things on user passwords"
    _types_= ["Person", "Computer"]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--bad-password-count",action="store_true", help="Find users whose bad password count is non-zero")
        parser.add_argument("--dump-unicode-pwd", action="store_true", help="Dump unicodePwd AD field")
        parser.add_argument("--password-age", nargs='?', const=-1, type=int, help="List the password age of all accounts")
        parser.add_argument("--last-logon", nargs='?', const=-1, type=int, help="List account unused for X days (No argument for listing)")
        parser.add_argument("--failed-logon", nargs='?', const=-1, type=int, help="List failed authentication since X days (No argument for listing)")
        parser.add_argument("--account-creation", action="store_true", help="List all account creation dates")
        parser.add_argument("--never-logged", action="store_true", help="List all account never used")
        parser.add_argument("--account-type", nargs='?', const=cls._types_[0], type=str, help="(%s)"%', '.join(cls._types_))
    
    def get_line(self, record, line):
    	res = [record.get(x,"-") if type(record.get(x,"-")) in [unicode,int,datetime] else unicode(str(record.get(x,"-")), errors='ignore').encode('hex') for x in line]
        res.append(SID2StringFull(record["objectSid"], self.guid))
        return res

    def dump_field(self, doc, field):
        t = doc.create_table("Dump of %s" % field)
        t.add(["name", field, "comments"])
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
            t.add(self.get_line(account, ["name", "whenCreated"]))
            t.flush()

    def extract_field_since(self, doc, field, since, account_type, invert=False):
        results=list()
        for r in self.datatable.find({field:{"$exists": True},"objectCategory":{"$in":[account_type]}}):
            cond = (datetime.now()-r[field]).days >= since
            if invert:
                cond = not cond
            if ( cond or since<0) :
                results.append(self.get_line(r, ["name", field]))

        t = doc.create_table("Dump of %s" % field)

        if len(results)==0:
            t.add(["No Result"])
            return
        else:
            t.add(["name", field, "comments"])
            t.add()
            for r in results:
                t.add(r)
                t.flush()

    def never_logged(self, doc, field, account_type):
        t = doc.create_table("Dump of %s" % field)
        t.add(["name"])
        t.add()
        for account in self.datatable.find({field:{"$exists":False},
                                            "objectCategory":{"$in":[account_type]}, 
                                            "$or":[{"isDeleted":False}, {"isDeleted":{"$exists":False}}]}):
            t.add(self.get_line(account, []))
            t.flush()


    def run(self, options, doc):


        if options.account_type not in self._types_:
            account_type=self.datatable.find_one({"name":self._types_[0] })["DNT_col"]
        else:
            account_type=self.datatable.find_one({"name":options.account_type})["DNT_col"]
        print account_type

        if options.bad_password_count:
            self.dump_field(doc, "badPwdCount")

        if options.failed_logon is not None:
            self.extract_field_since(doc, "badPasswordTime", options.failed_logon)

        if options.password_age is not None:
            arg=options.password_age
            self.extract_field_since(doc, "pwdLastSet", abs(arg), arg<0)

        if options.last_logon is not None:
            self.extract_field_since(doc, "lastLogonTimestamp", options.last_logon, account_type)

        if options.account_creation:
            self.account_creation_date(doc, account_type)

        if options.dump_unicode_pwd:
            self.dump_field(doc, "unicodePwd")

        if options.never_logged:
            self.never_logged(doc, "lastLogonTimestamp", account_type)
    
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "badPwdCount", int)
        self.assert_field_type(self.datatable, "sAMAccountName", str, unicode)
        self.assert_field_type(self.datatable, "name", str, unicode)
