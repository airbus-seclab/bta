from ntds.miners import Miner
from collections import defaultdict

SDTABLE="sdtable2"
DATATABLE="datatable5"

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
    
    def run(self, options):

        dt = options.db.db[DATATABLE]
        sd = options.db.db[SDTABLE]
    
        match = {}
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
                        users[sid].add(HRec(r))
        
        for sid,lsd in sorted(users.iteritems(), key=lambda x,y:len(y)):
            print "+ %s" % sid
            for sd in lsd:
                print "    id=%(id)i refcount=%(refcount)i hash=%(hash)s" % sd.rec
