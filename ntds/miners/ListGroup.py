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

    def get_members_of(self, grpsid, recursive=False):
        group = self.dt.find_one({ 'objectSid': grpsid})
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
                    members.update(self.get_members_of(sid, recursive=True))
                    self.groups_already_saw[sid] = True
            elif row['objectCategory'] == '3818':
                fromgrp = grpsid if recursive else ''
                membership = (row['objectSid'], deleted, fromgrp)
                members.add(membership)
            else:
                print '***** Unknown category (%s) for %s' % (row['objectCategory'], sid)
        return members

    def run(self, options, doc):
        def deleted_last(l):
            deleteditems=[]
            for i in l:
                if not i[1]:
                    yield i
                else:
                    deleteditems.append(i)
            for i in deleteditems:
                yield i
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
            for sid,deleted,fromgrp in deleted_last(membership):
                sidobj = Sid(dt, objectSid=sid)
                member = str(sidobj)
                if deleted:
                    member += " deleted %s" % deleted
                if fromgrp:
                    member += ' [%s]' % (Sid(dt, objectSid=fromgrp))
                sublist.add('{0} {1}'.format(member, misc))
            sublist.finished()
