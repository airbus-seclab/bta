from bta.miners import Miner
from collections import defaultdict

@Miner.register
class Membership(Miner):
    _name_ = "Membership"
    _desc_ = "List group membership"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--match", help="Look only for users matching REGEX", metavar="REGEX")

    def run(self, options, doc):
        match = None

        table = doc.create_table("group membership")

        match = { 'objectSid': {'$exists': True}, 'primaryGroupID': {'$exists': True},  }
        if options.match is not None:
            match = {"$and": [ match,
                              {"$or": [ { "cn": { "$regex": options.match } },
                                       { "objectSid": { "$regex": options.match } }
                                     ]}
                             ]
            }

        for user in self.datatable.find(match):
             links = self.linktable.find({'backlink_DNT': user['RecId']}, {'link_DNT': True})
             groups=set()
             sid = user['objectSid']
             pgid = sid[:sid.rfind('-') + 1] + user['primaryGroupID']
             primarygroup = self.datatable.find_one({'objectSid': pgid}, {'cn': True})
             groups.add(primarygroup['cn'])
             for link in links:
                 groupRecId = link['link_DNT']
                 group = self.datatable.find_one({'RecId': groupRecId, 'cn':{"$exists":True}}, {'cn': True})
                 if group:
                     groups.add(group['cn'])
             table.add([user["objectSid"], user["cn"], ', '.join(groups)])
        table.finished()
