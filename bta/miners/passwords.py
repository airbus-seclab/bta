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
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--bad-password-count", action="store_true", help="Find users whose bad password count is non-zero")
        parser.add_argument("--dump-unicode-pwd", action="store_true", help="Dump unicodePwd AD field")
        parser.add_argument("--password-age", action="store_true", help="List the password age of all accounts")
        parser.add_argument("--last-logon", nargs='?', const=-1, type=int, help="List account unused for X days (No argument for listing)")
        parser.add_argument("--account-creation", action="store_true", help="List all account creation dates")
    
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

    def account_creation_date(self, doc):
        t = doc.create_table("Account creation date")
        t.add(["name", "whenCreated", "comments"])
        t.add()
        for account in self.datatable.find({"whenCreated":{"$exists":True}, 
                                            "objectClass":{"$in":["2.5.6.7"]}, 
                                            "$or":[{"isDeleted":False}, {"isDeleted":{"$exists":False}}]}):
            t.add(self.get_line(account, ["name", "whenCreated"]))
            t.flush()

    def last_logon(self, doc, field, since):
        results=list()
        for r in self.datatable.find({field:{"$exists": True}}):
            if ( (datetime.now()-r[field]).days >= since or since<0):
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


    def run(self, options, doc):
        if options.bad_password_count:
            self.dump_field(doc, "badPwdCount")

        if options.password_age:
            self.dump_field(doc, "pwdLastSet")

        if options.last_logon>=0:
            self.last_logon(doc, "lastLogonTimestamp", options.last_logon)

        if options.account_creation:
            self.account_creation_date(doc)

        if options.dump_unicode_pwd:
            self.dump_field(doc, "unicodePwd")
    
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "badPwdCount", int)
        self.assert_field_type(self.datatable, "sAMAccountName", str, unicode)
        self.assert_field_type(self.datatable, "name", str, unicode)
