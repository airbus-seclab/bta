from ntds.miners import Miner
from ntds.miners.tools import User, Group, Sid


@Miner.register
class ListGroup(Miner):
    _name_ = "ListGroup"
    _desc_ = "List group membership"
    groups_already_saw={}

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--match", help="Look only for groups matching REGEX", metavar="REGEX")
        parser.add_argument("--noresolve", help="Do not resolve SID", action="store_true")
        parser.add_argument("--verbose", help="Show also deleted users time and RID", action="store_true")

    def get_members_of(self, sid):
        group = self.dt.find_one({ 'objectSid': sid})
        if not group:
            return set()
        members=set()
        for link in self.lt.find({'link_DNT': group['RecId']}):
            deleted=False
            if 'link_deltime' in link and link['link_deltime'].year > 1970:
                deleted = link['link_deltime']
            row = self.dt.find_one({'RecId': link['backlink_DNT'] })
            if not row:
                members.add('[no entry %d found]' % link['backlink_DNT'])
                continue
            sid = row['objectSid']
            if row['objectCategory'] == '5945':
                if sid not in self.groups_already_saw:
                    members.update(self.get_members_of(sid))
                    self.groups_already_saw[sid] = True
            elif row['objectCategory'] == '3818':
                membership = (row['objectSid'], deleted)
                members.add(membership)
            else:
                print '***** Unknown category (%s) for %s' % (row['objectCategory'], sid)
        return members

    def run(self, options, doc):
        self.dt = dt = options.backend.open_table("datatable")
        self.lt = lt = options.backend.open_table("linktable")
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
             groups[group['objectGUID']] = self.get_members_of(group['objectSid'])

        misc=''
        glist = doc.create_list("")
        for groupname,membership in groups.items():
            group = Sid(dt, objectGUID=groupname, verbose=options.verbose)
            glist.add(group)
            sublist = glist.create_list("")
            for sid,deleted in membership:
                sidobj = Sid(dt, objectSid=sid)
                member = str(sidobj)
                if options.verbose and deleted:
                    member += " deleted %s" % deleted
                sublist.add('{0} {1}'.format(member, misc))
            sublist.finished()
