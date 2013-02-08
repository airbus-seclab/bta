from ntds.miners import Miner
from collections import defaultdict

class HRec: # wraps sd entries to make them hashable
    def __init__(self, rec):
        self.rec = rec
    def __hash__(self):
        return hash(self.rec["hash"])



@Miner.register
class SDusers(Miner):
    _name_ = "SDusers"
    _desc_ = "List users in SD"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--match", help="Look only for users matching REGEX", metavar="REGEX")
        parser.add_argument("--verbose", action="store_true", help="List security descriptors for each user")
    
    def run(self, options, doc):

        sd = options.backend.open_table("sdtable")
        dt = options.backend.open_table("datatable")
    
        match = None
        if options.match:
            match = {"$or": [
                    { "value.DACL.ACEList":
                          {"$elemMatch":
                               {"SID": { "$regex": options.match } }
                           }
                      },
                    { "value.SACL.ACEList":
                          {"$elemMatch":
                               {"SID": { "$regex": options.match } }
                           }
                      },
                    ] }
                    
        users = defaultdict(lambda:set())
        
        for r in sd.find(match):
            for aclt in "SACL","DACL":
                if r["value"] and aclt in r["value"]:
                    for ace in r["value"][aclt]["ACEList"]:
                        sid = ace["SID"]
                        # XXX check sid matches regex
                        users[sid].add(HRec(r))

        table = doc.create_table("Users present in security descriptors")
        table.add(["SID","# of SD", "SID obj names", "SID obj creation dates"])
        table.add()
        
        for sid,lsd in sorted(users.iteritems(), key=lambda (x,y):len(y)):
            c = dt.find({"objectSid":sid}) #, "name":{"$exists":True}})
            names = set([ r["name"] for r in c if "name" in r])
            c.rewind()
            dates = set([ r["whenCreated"].ctime() for r in c if "whenCreated" in r])
            table.add([sid, str(len(lsd)), " | ".join(names), " | ".join(dates)])
#            if options.verbose:
#                for sd in lsd:
#                    print "    id=%(id)7i refcount=%(refcount)4i hash=%(hash)s" % sd.rec
