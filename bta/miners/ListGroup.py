# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.miners import ListACE
from bta.miners.tools import Sid
import datetime
from bta.tools.WellKnownSID import SID2StringFull, SID2String

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
        group = self.datatable.find_one({'objectSid': grpsid.split(":")[0]})
        if not group:
            return set()
        members=set()
        for link in self.link_table.find({'link_DNT': group['DNT_col']}):
            deleted=False
            if 'link_deltime' in link and link['link_deltime'].year > 1970:
                deleted = link['link_deltime']
            row = self.datatable.find_one({'DNT_col': link['backlink_DNT']})
            if not row:
                members.add('[no entry %d found]' % link['backlink_DNT'])
                continue
            sid = row['objectSid']
            category = row['objectCategory']
            if category == self.categories.group:
                if sid not in self.groups_already_saw:
                    self.groups_already_saw[sid] = True
                    members.update(self.get_members_of(sid+":"+grpsid, recursive=True))
            elif category == self.categories.person:
                fromgrp = grpsid if recursive else ''
                name=row['cn']
                membership = (sid, deleted, fromgrp, name)
                members.add(membership)
            else:
                print '***** Unknown category (%d) for %s' % (category, sid)
        if len(members)==0:
            members.add((grpsid.split(":")[0],'empty','',SID2StringFull(grpsid.split(":")[0], self.guid)))
        return members

    def getInfo_fromSid(self, sid):
        return self.datatable.find_one({'objectSid': sid})

    def find_dn(self, r):
        if not r:
            return ""
        cn = r.get("cn") or r.get("name")
        if cn is None or cn.startswith("$ROOT_OBJECT$"):
            return ""
        r2 = self.datatable.find_one({"DNT_col":r["PDNT_col"]})
        return self.find_dn(r2)+"."+cn

    def checkACE(self,membersid):
        secDesc = int(self.datatable.find_one({"objectSid": membersid })['nTSecurityDescriptor'])
        hdlACE = ListACE.ListACE(self.backend)
        securitydescriptor = hdlACE.getSecurityDescriptor(secDesc)
        aceList = hdlACE.extractACE(securitydescriptor)

        Mylist = list()
        for ace in aceList:
            info = self.getInfo_fromSid(ace['SID'])
            if info is None:
                trustee_cn = trustee_string = "NULLOBJECT-%s" % ace['SID']
            else:
                if "cn" in info:
                    trustee_cn=info['cn']
                    trustee_string=SID2String(info['cn'])
                else:
                    trustee_string = trustee_cn = info['name']
            trustee = trustee_cn if trustee_cn==trustee_string else "%s (%s)"%(trustee_cn, trustee_string)
            info2 = self.getInfo_fromSid(membersid)
            subject = info2['cn']
            if ace['ObjectType']:
                objtype = hdlACE.type2human(ace['ObjectType'])
            else:
                objtype = '(none)'
            Mylist.append([trustee, subject, ace['Type'], objtype])
        return Mylist

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

        match = None

        doc.add("List of groups matching [%s]" % options.match)
        if options.match:
            match = {"$and": [{'objectCategory': self.categories.group},
                              {"$or": [ { "name": { "$regex": options.match } },
                                       { "objectSid": { "$regex": options.match } }
                                     ]}]
            }

        groups={}
        for group in self.datatable.find(match):
            groups[group['objectSid']] = set()
            groups[group['objectSid']] = self.get_members_of(group['objectSid'])

        headers=['User', 'Deletion', 'Flags', 'Recursive']

        listemptyGroup=[]
        for groupSid,membership in groups.items():
            if len(membership)==0:
                listemptyGroup.append(groupSid)
                continue
            info = self.getInfo_fromSid(groupSid)
            name = info['cn']
            guid = info['objectGUID']
            sec = doc.create_subsection("Group %s" % name)
            sec.add("sid = %s" % groupSid)
            sec.add("guid = %s" % guid)
            sec.add("cn = %s" % self.find_dn(info))
            table = sec.create_table("Members of %s" % name)
            table.add(headers)
            table.add()
            for sid,deleted,fromgrp,name in deleted_last(membership):
                fromgrp = fromgrp.split(":")[0]
                sidobj = Sid(sid, self.datatable)
                member = unicode(sidobj)
                if fromgrp:
                    fromgrp = Sid(fromgrp, self.datatable)
                flags = sidobj.getUserAccountControl()
                table.add((member, deleted or '', flags if flags!='' else 'emptygroup', fromgrp))
            table.finished()

            for sid,deleted,fromgrp,name in deleted_last(membership):
                sec.add("User %s (%s)" % (name, sid))
                table = sec.create_table("ACE")
                table.add(["Trustee", "Member", "ACE Type", "Object type"])
                table.add()
                listACE=self.checkACE(sid)
                for ace in listACE:
                    table.add(ace)
                table.finished()
            sec.finished()

        if len(listemptyGroup) > 0:
            headers=['Group', 'SID', 'Guid']
            table = doc.create_table("Empty groups")
            table.add(headers)
            table.add()
            print "@@@",listemptyGroup
            for groupSid in listemptyGroup:
                info = self.getInfo_fromSid(groupSid)
                name = info['cn']
                guid = info['objectGUID']
                table.add((name, groupSid, guid))
            table.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "objectSid", str, unicode)
        self.assert_field_type(self.datatable, "DNT_col", int)
        self.assert_field_type(self.datatable, "PDNT_col", int)
        self.assert_field_type(self.datatable, "objectCategory", int)
        self.assert_field_type(self.datatable, "cn", str, unicode)
        self.assert_field_type(self.datatable, "name", str, unicode)
        self.assert_field_type(self.datatable, "objectGUID", str, unicode)
        self.assert_field_type(self.sd_table, "link_DNT", int)
        self.assert_field_type(self.sd_table, "link_deltime", datetime.datetime)
        self.assert_field_type(self.sd_table, "backlink_DNT", int)
