# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from collections import defaultdict
import datetime

class HRec: # wraps sd entries to make them hashable
    def __init__(self, rec):
        self.rec = rec
    def __hash__(self):
        return hash(self.rec["sd_hash"])



@Miner.register
class SDusers(Miner):
    _name_ = "SDusers"
    _desc_ = "List users in SD"
    _uses_ = [ "raw.datatable", "raw.sd_table" ]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--match", help="Look only for users matching REGEX", metavar="REGEX")

    def run(self, options, doc):
        match = None
        if options.match:
            match = {"$or": [
                    { "sd_value.DACL.ACEList":
                          {"$elemMatch":
                               {"SID": { "$regex": options.match } }
                           }
                      },
                    { "sd_value.SACL.ACEList":
                          {"$elemMatch":
                               {"SID": { "$regex": options.match } }
                           }
                      },
                    ] }

        users = defaultdict(lambda:set())

        for r in self.sd_table.find(match):
            for aclt in "SACL","DACL":
                if r["sd_value"] and aclt in r["sd_value"]:
                    for ace in r["sd_value"][aclt]["ACEList"]:
                        sid = ace["SID"]
                        # XXX check sid matches regex
                        users[sid].add(HRec(r))

        table = doc.create_table("Users present in security descriptors")
        table.add(["SID","# of SD", "SID obj names", "SID obj creation dates"])
        table.add()

        for sid,lsd in sorted(users.iteritems(), key=lambda (x,y):len(y)):
            c = self.datatable.find({"objectSid":sid}) #, "name":{"$exists":True}})
            names = set([ r["name"] for r in c if "name" in r])
            c.rewind()
            dates = set([ r["whenCreated"].ctime() for r in c if "whenCreated" in r])
            table.add([sid, str(len(lsd)), ", ".join(names), ", ".join(dates)])

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "objectSid")
        self.assert_field_type(self.datatable, "objectSid", str, unicode)
        self.assert_field_exists(self.datatable, "name")
        self.assert_field_type(self.datatable, "name", str, unicode)
        self.assert_field_exists(self.datatable, "whenCreated")
        self.assert_field_type(self.datatable, "whenCreated", datetime.datetime)
        self.assert_field_exists(self.sd_table, "sd_value.DACL.ACEList.SID")
        self.assert_field_exists(self.sd_table, "sd_value.SACL.ACEList.SID")
