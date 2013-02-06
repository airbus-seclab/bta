from ntds.miners import Miner
from collections import defaultdict

@Miner.register
class ListGroup(Miner):
    _name_ = "ListGroup"
    _desc_ = "List group membership"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--match", help="Look only for groups matching REGEX", metavar="REGEX")

    def run(self, options):
        dt = options.backend.open_table("datatable")
        lt = options.backend.open_table("linktable")
        match = None

        if options.match:
            match = {"$and": [{'objectCategory': '5945'},
                              {"$or": [ { "name": { "$regex": options.match } },
                                       { "objectSid": { "$regex": options.match } }
                                     ]}]
            }

        groups={}
        for group in dt.find(match):
             groups[group['objectGUID']]=set()
             for link in lt.find({'link_DNT': group['RecId']}, {'backlink_DNT': True}):
                 groups[group['objectGUID']].add(link['backlink_DNT'])

        for groupname,members in groups.items():
             s=u"{0:50} {1}".format(groupname, ', '.join(map(str, members)))
             print s.encode('utf-8')
