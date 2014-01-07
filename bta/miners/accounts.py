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
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--created-since", nargs='?', const=-1, type=int, help="List account created from X days (no argument for listing)")
        parser.add_argument("--changed-since", nargs='?', const=-1, type=int, help="List account changed from X days (no argument for listing)")
    
    def get_line(self, record, line):
    	res = [record.get(x,"-") if type(record.get(x,"-")) in [unicode,int,datetime] else unicode(str(record.get(x,"-")), errors='ignore').encode('hex') for x in line]
        res.append(SID2StringFull(record["objectSid"], self.guid))
        return res

    def extract_field_since(self, doc, field, since, types):
        results=list()
        for r in self.datatable.find({field:{"$exists": True},"objectClass":{"$in":types}}):
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

        if options.created_since is not None:
            self.extract_field_since(doc, "whenCreated", options.created_since, ["2.5.6.7"])
    
        if options.changed_since is not None:
            self.extract_field_since(doc, "whenChanged", options.created_since, ["2.5.6.7"])

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "name", str, unicode)
