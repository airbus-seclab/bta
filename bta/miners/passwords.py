# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miners import Miner
from collections import defaultdict


@Miner.register
class Passwords(Miner):
    _name_ = "passwords"
    _desc_ = "Look for things on user passwords"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--bad-password-count", action="store_true", help="Find users whose bad password count is non-zero")
        parser.add_argument("--dump-unicode-pwd", action="store_true", help="Dump unicodePwd AD field")
    
    def get_line(self, record, line):
        return [unicode(record.get(x,"-")) for x in line]

    def bad_password_count(self, doc):
        t = doc.create_table("Users whose badPwdCount is non-zero")
        for r in self.datatable.find({"badPwdCount":{"$exists": True, "$ne":0}}): #.sort({"badPwdCount":1}):
            t.add(self.get_line(r, ["sAMAccountName", "name", "badPwdCount"]))
            t.flush()

    def dump_field(self, doc, field):
        t = doc.create_table("Dump of %s" % field)
        for r in self.datatable.find({field:{"$exists": True}}):
            t.add(self.get_line(r, ["sAMAccountName", "name", field]))
            t.flush()

    def run(self, options, doc):
        if options.bad_password_count:
            self.bad_password_count(doc)
        if options.dump_unicode_pwd:
            self.dump_field(doc, "unicodePwd")
    
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "badPwdCount", int)
        self.assert_field_type(self.datatable, "sAMAccountName", str, unicode)
        self.assert_field_type(self.datatable, "name", str, unicode)