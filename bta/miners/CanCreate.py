# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
from bta.tools.WellKnownSID import SID2StringFull
from bta.miners.tools import Family
from bta.miners.tools import ObjectClass

@Miner.register
class CanCreate(Miner):
    _name_ = "CanCreate"
    _desc_ = "This miner list all user who possess the right to create objects"
    
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--root', help='Distinguished name for the search start')
        parser.add_argument("--rec", help="Recursive search deapth (-1 = infinite)")
        parser.add_argument('--obj', help='Type of object we can create (Common name needed) for exemple : User, Compter, Print-Queue, Group, Organizational-Unit, Container, Contact, ...')
    
    def ACECreationRight(self, searchedType):
        result = dict()
        
        req = {'sd_value.DACL.ACEList.AccessMask.flags.ADSRightDSCreateChild':True}
        req_filter = {'sd_value.DACL.ACEList.SID':1, 
                  'sd_value.DACL.ACEList.AccessMask.flags.ADSRightDSCreateChild':1, 
                  'sd_id':1,
                  'sd_value.DACL.ACEList.ObjectType':1,
                  'sd_value.DACL.ACEList.Type':1}
        for sd in self.sd_table.find(req,req_filter):
            # Making the list of deny access
            denied_ace=list()
            for ace in sd["sd_value"]["DACL"]["ACEList"]:
                if ace["Type"] == "AccessDeniedObject" and ace["AccessMask"]["flags"]["ADSRightDSCreateChild"]:
                    denied_ace.append((ace["SID"],SID2StringFull(ace["ObjectType"],self.datatable,only_converted=True)))

            result[u"%s"%sd["sd_id"]]=list()
            for ace in sd["sd_value"]["DACL"]["ACEList"]:
                who = ace["ObjectType"] if "ObjectType" in ace.keys() else "EVERYTHING !"
                if (ace["SID"],searchedType) not in denied_ace:
                    string_who=SID2StringFull(who,self.datatable,only_converted=True)
                    if (ace["AccessMask"]["flags"]["ADSRightDSCreateChild"] and string_who in [searchedType, "EVERYTHING !"]):
                        result[u"%s"%sd["sd_id"]].append("%s have the right to create %s"%(SID2StringFull(ace["SID"],self.datatable),string_who))
        return result

    def run(self, options, doc):
        if options.obj is None or options.obj=="":
            print "Usage <obj> is required !"
            exit(1)

        SDs_can_create = self.ACECreationRight(options.obj)
        #print SDs_can_create
        possibleSupperiors = ObjectClass.find_my_possuperiors(options.obj, self.datatable)
        #print possibleSupperiors
        selected_instances = {}
        for classGovernsID in possibleSupperiors:
            selected_instances.update(ObjectClass.instanceOfClass(classGovernsID, self.datatable))
        depth = 1
        if options.rec:
            depth=int(options.rec)
        if(options.root):
            the_node = Family.find_the_one(options.root, self.datatable)
            tree = Family.find_offspring(the_node,self.datatable,depth, need=['name', 'DNT_col', 'nTSecurityDescriptor'])
        l = doc.create_list("Node information")
        Family.correlate(tree, [(2, SDs_can_create), (1, selected_instances)], l, self.datatable)
        l.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "objectCategory")
        self.assert_field_type(self.datatable, "objectCategory", int)
        self.assert_field_exists(self.datatable, "whenCreated")
        self.assert_field_type(self.datatable, "name", str, unicode)
        self.assert_field_type(self.datatable, "userAccountControl", dict)
        self.assert_field_type(self.datatable, "cn", str, unicode)
