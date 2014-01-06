# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
from bta.tools.WellKnownSID import SID2StringFull, Strings2SID
from bta.miners.tools import Family
from bta.miners.tools import ObjectClass

@Miner.register
class Search4Rights(Miner):
    _name_ = "Search4Rights"
    _desc_ = "This miner list all user who possess a certain right on User and Computer objects"
    _rights_ = {'User-Force-Change-Password':['ADSRightDSControlAccess'], 
                'Send-As':['ADSRightDSControlAccess'], 
                'Receive-As':['ADSRightDSControlAccess'], 
                'User-Account-Control':['GenericAll','ADSRightDSWriteProp', 'GenericWrite'],
                'Lockout-Time':['GenericWrite', 'ADSRightDSWriteProp', 'GenericAll'],
                'Script-Path':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'Logon-Hours':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'User-Workstations':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'Account-Expires':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'User-Account-Control':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'User-Principal-Name':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'Service-Principal-Name':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'Group':['ADSRightDSCreateChild'],
                'Member':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'Self-Membership':['ADSRightDSSelf'],
                'Group-Type':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'GP-Link':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                'GP-Options':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                #'':['GenericWrite','ADSRightDSWriteProp', 'GenericAll'],
                }
    _types_ = ["User", "Computer", "Group"]
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--root', help='Distinguished name for the search start')
        parser.add_argument("--rec", help="Recursive search deapth (-1 = infinite)")
        parser.add_argument('--right', help='Right you want to search for: %s : '%', '.join(cls._rights_.keys()))
        parser.add_argument('--obj', help='Type of object the right apply on : %s'%', '.join(cls._types_))
    
    def ACEAllowRight(self, searchedRight, flags, searchedType):
        magic_word="everything"
        result = dict()
        from pprint import pprint
        flags4Req=[{'sd_value.DACL.ACEList.AccessMask.flags.%s'%flag:True} for flag in flags]
        type4Req={'sd_value.DACL.ACEList.InheritedObjectType':{'$in':Strings2SID(searchedType,self.guid)}}
        req = {'$and':[{'$or':[type4Req, {'sd_value.DACL.ACEList.InheritedObjectType':{'$exists':False}}]}, {'$or':flags4Req}]}
        req_filter = {'sd_value.DACL.ACEList.SID':1, 
                  'sd_value.DACL.ACEList.AccessMask.flags':1, 
                  'sd_id':1,
                  'sd_value.DACL.ACEList.ObjectType':1,
                  'sd_value.DACL.ACEList.Type':1}
        #pprint(req)
        #pprint(req_filter)
        for sd in self.sd_table.find(req,req_filter):
            # Making the list of deny access
            denied_ace=list()
            for ace in sd["sd_value"]["DACL"]["ACEList"]:
                if (any([ace["AccessMask"]["flags"].get(flag, False) for flag in flags]) and ace["Type"] == "AccessDeniedObject"):
                    who = ace["ObjectType"] if "ObjectType" in ace.keys() else magic_word
                    denied_ace.append((ace["SID"],SID2StringFull(who,self.guid,only_converted=True)))

            for ace in sd["sd_value"]["DACL"]["ACEList"]:

                if "InheritedObjectType" not in ace.keys():
                    ace["InheritedObjectType"]=magic_word
                elif SID2StringFull(ace["InheritedObjectType"],self.guid,only_converted=True) != searchedType:
                    continue
                if (((ace["SID"],magic_word) in denied_ace) or ((ace["SID"],searchedRight) in denied_ace)):
                    continue

                who = ace["ObjectType"] if "ObjectType" in ace.keys() else magic_word
                string_who=SID2StringFull(who,self.guid,only_converted=True)
                if ( any([ace["AccessMask"]["flags"].get(flag, False) for flag in flags]) and string_who in [searchedRight, magic_word]):
                    # Create the dictionary if necessary
                    if u"%s"%sd["sd_id"] not in result.keys():
                        result[u"%s"%sd["sd_id"]]=list()
                    result[u"%s"%sd["sd_id"]].append("----------%s have the right %s on %s"%(SID2StringFull(ace["SID"],self.guid), 
                                                                                             string_who, 
                                                                                             SID2StringFull(ace["InheritedObjectType"],
                                                                                             self.guid)))
        pprint(result)
        return result

    def run(self, options, doc):
        if options.obj is None or options.obj not in self._types_:
            print "Usage <obj> is required ! and must be in %s "%', '.join(self._types_)
            exit(1)
        if options.right is None or options.right not in self._rights_.keys():
            print "Usage <right> is required ! and must be in %s "%', '.join(self._rights_.keys())
            exit(1)

        SDs_can_create = self.ACEAllowRight(options.right, self._rights_[options.right], options.obj)
        #print SDs_can_create
        depth = 1
        if options.rec:
            depth=int(options.rec)
        if(options.root):
            root=unicode(options.root, errors='ignore')
        else:
            print "Root argument not found !"
            exit(1)
            
        the_node = Family.find_the_one(root, self.datatable)
        if the_node is not None:
            tree = Family.find_offspring(the_node,self.datatable,depth, need=['name', 'DNT_col', 'nTSecurityDescriptor'])
        else:
            print "Check your root %s not found !"%root
            exit(1)

        l = doc.create_list("Node information")
        #Family.correlate(tree, [(2, SDs_can_create), (1, selected_instances)], l, self.datatable)
        Family.correlate(tree, [(2, SDs_can_create)], l, self.datatable)
        l.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "objectCategory")
        self.assert_field_type(self.datatable, "objectCategory", int)
        self.assert_field_exists(self.datatable, "whenCreated")
        self.assert_field_type(self.datatable, "name", str, unicode)
        self.assert_field_type(self.datatable, "userAccountControl", dict)
        self.assert_field_type(self.datatable, "cn", str, unicode)
