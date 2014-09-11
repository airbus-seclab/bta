# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from datetime import datetime
from bta.tools.mtools import Family
from bta.tools.WellKnownSID import SID2StringFull
import re

@Miner.register
class PasswordPolicy(Miner):
    _name_ = "PasswordPolicy"
    _desc_ = "Describe all the password policy of a domain"
    _uses_ = [ "raw.datatable", "raw.sd_table" ]
    _ListOfAttributes_=["pwdHistoryLength",
                        "maxPwdAge",
                        "lockoutDuration",
                        "minPwdAge",
                        "lockOutObservationWindow",
                        "minPwdLength",
                        "gPLink",
                        ]
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--cn', help='scpecify the domain')

    def extractGpLinks(self, gp_attr):
        regex=r"\[LDAP://(?P<CN>[^;]*);(?P<activated>\d)\]"
        m=re.findall(regex, gp_attr)
        res=list()
        for (link_DN, activation) in m:
            convertion = self.dnames.find_one({"DName":{"$regex":"^%s"%link_DN,"$options":"i"}})
            res.append((link_DN, convertion, activation))
        return res

    def run(self, options, doc):
        if not options.cn:
            print "The root is mandatory, you need to specify the \"cn\" argument"
            exit(1)
        the_node=Family.find_the_one(options.cn, self.datatable)
        t = doc.create_list("The password policy for the domain %s is" % options.cn)
        gplinks=list()
        # Display all attributes in _ListOfAttributes_
        for att in self._ListOfAttributes_:
            att_value=""
            if (att in the_node.keys()):
                if isinstance(the_node[att],datetime):
                    att_value = str(the_node[att]-datetime.fromtimestamp(0))
                else:
                    att_value = the_node[att]
                if att == "gPLink":
                    tt = t.create_list("The attribute %s contains"%att)
                    gplinks = self.extractGpLinks(the_node[att])
                    for l in gplinks:
                        tt.add("%s %s"%(l[0],l[2]))
                else:
                    t.add("The attribute %s has the value %s"%(att, att_value))
        t.add()
        # Find the ACL of each gplink
        for gplink in gplinks:
            the_link = self.datatable.find_one({"DNT_col":gplink[1]["DNT_col"]})
            the_link_acl = self.sd_table.find_one({"sd_id":the_link["nTSecurityDescriptor"]})
            ttt=doc.create_list("The ACL of the group policy container %s are" % gplink[0])
            for ace in the_link_acl["sd_value"]["DACL"]["ACEList"]:
                tttt=ttt.create_list("%s has the right %s on %s"%(SID2StringFull(ace["SID"],self.guid),
                                                                  ace["Type"],
                                                                  SID2StringFull(ace.get("ObjectType","everything"),self.guid,only_converted=True)))
                for flag in [a for a,b in ace["AccessMask"]["flags"].items() if b]:
                    tttt.add("%s"%flag)

            ttt.add()

        t.flush()
        t.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "cn", str, unicode)
