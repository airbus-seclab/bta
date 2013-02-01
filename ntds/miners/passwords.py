from ntds.miners import Miner
from collections import defaultdict


@Miner.register
class Passwords(Miner):
    _name_ = "passwords"
    _desc_ = "Look for things on user passwords"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--bad-password-count", action="store_true", help="Find users whose bad password count is non-zero")
        parser.add_argument("--dump-unicode-pwd", action="store_true", help="Dump unicodePwd AD field")
    
    def print_user(self, record, field=None):
        fmt = "%(sAMAccountName)-20s %(name)-50s"
        d = defaultdict(lambda:"-")
        d.update(record)
        if field:
            fmt += " %%(%s)s" % field
        print fmt % d
    
    def bad_password_count(self):
        for r in self.dt.find({"badPwdCount":{"$exists": True, "$ne":"0"}}): #.sort({"badPwdCount":1}):
            self.print_user(r, "badPwdCount")

    def dump_field(self, field):
        for r in self.dt.find({field:{"$exists": True}}):
            self.print_user(r, field)
            

    def run(self, options):
        self.dt = options.backend.open_table("datatable")

        if options.bad_password_count:
            self.bad_password_count()
        if options.dump_unicode_pwd:
            self.dump_field("unicodePwd")
