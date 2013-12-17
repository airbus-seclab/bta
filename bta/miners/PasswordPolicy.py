# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
from datetime import datetime, timedelta
from bta.miners.tools import Family
import re

@Miner.register
class PasswordPolicy(Miner):
    _name_ = "PasswordPolicy"
    _desc_ = "Describe all the password policy of a domain"
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
        regex="\[LDAP://(?P<CN>[^;]*);(?P<activated>\d)\]"
        m=re.findall(regex, gp_attr)
        res=""
        for link in m:
            res+="%s %s "% (link[0], link[1])
        print self.dnames.find({"DName":{"$regex":link[0],"$options":"i"}},{"DNT_col":1})
        return res
    
    def run(self, options, doc):
        if not options.cn:
            print "the root is mandatory"
            exit(1)
        the_node=Family.find_the_one(options.cn, self.datatable)
        t = doc.create_list("The password policy for the domain %s is" % options.cn)
        for att in self._ListOfAttributes_:
            att_value="Not set !"
            if (att in the_node.keys()): 
                if isinstance(the_node[att],datetime):
                    att_value = str(the_node[att]-datetime.fromtimestamp(0))
                elif att=="gPLink":
                    att_value = self.extractGpLinks(the_node[att])
                else:
                    att_value = the_node[att] 
            t.add("the attribute %s has the value %s"%(att, att_value))
        t.flush()
        t.finished()
        
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "cn", str, unicode)
