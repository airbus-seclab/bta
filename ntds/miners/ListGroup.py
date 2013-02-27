from ntds.miners import Miner
from collections import defaultdict
from ntds.miners.tools import User, Group, Sid

@Miner.register
class ListGroup(Miner):
    _name_ = "ListGroup"
    _desc_ = "List group membership"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--match", help="Look only for groups matching REGEX", metavar="REGEX")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")

    def run(self, options, doc):
        dt = options.backend.open_table("datatable")
        lt = options.backend.open_table("linktable")
        match = None
        
        doc.add("List of groups matching [%s]" % options.match)
        
        if options.match:
            match = {"$and": [{'objectCategory': '5945'},
                              {"$or": [ { "name": { "$regex": options.match } },
                                       { "objectSid": { "$regex": options.match } }
                                     ]}]
            }

        groups={}
        for group in dt.find(match):
             groups[group['objectGUID']]=set()
             for link in lt.find({'link_DNT': group['RecId']}):
                 deleted=False
                 if 'link_deltime' in link and link['link_deltime'].year > 1970:
                     deleted = link['link_deltime']
                 membership = (User(dt, RecId=link['backlink_DNT']), deleted)
                 groups[group['objectGUID']].add(membership)

        misc=''
        glist = doc.create_list("")
        for groupname,membership in groups.items():
            if not options.noresolve:
                group = Group(dt, objectGUID=groupname)
                glist.add("%s %s" % (Sid.resolveRID(group.objectSid), group.cn))
            else:
                glist.add(groupname)
            sublist = glist.create_list("")
            for member,deleted in membership:
                if options.noresolve:
                    member = member.objectSid
                else:
                    sid = Sid.resolveRID(member.objectSid)
                    member = '{0:50} {1[cn]}'.format(sid, member)
                if options.verbose and deleted:
                    member += " deleted %s" % deleted
                sublist.add('{0} {1}'.format(member, misc))
            sublist.finished()
