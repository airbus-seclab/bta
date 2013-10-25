# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
from struct import unpack_from
from base64 import b64decode
import bson.binary

@Miner.register
class DNTree(Miner):
    _name_ = "DNTree"
    _desc_ = "DN Tree"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--cn", help="Look for objects with given CN and print their DN")
        parser.add_argument("--rec", help="Recursive search deapth (-1 = infinite)")
        parser.add_argument("--ace", help="Display ACEs")
    
    def run(self, options, doc):
        doc.add("Display the tree of all objects in the database")


        def find_parents(node):
            parents=list()
            for a in node['Ancestors_col']:
                parents.append(self.datatable.find({"DNT_col":a}).limit(1)[0])
            return parents

        def find_siblings(node):
            siblings=list()
            id_siblings=[s["DNT_col"] for s in self.datatable.find({"PDNT_col":node['DNT_col']},{"DNT_col":1})]
            for i in id_siblings:
                siblings.append(self.datatable.find({"DNT_col":i}).limit(1)[0])

            return siblings

        def pretty(d, doc, indent=0):
            for key, value in d.iteritems():
                if isinstance(value, dict):
                    l_o=doc.create_list(key)
                    pretty(value, l_o, indent+1)
                    l_o.finished()
                elif isinstance(value, list):
                    l_o=doc.create_list(key)
                    count=1
                    for i in value:
                        pretty({u"%s_%d"%(key,count):i},l_o, indent+1)
                        count += 1
                    l_o.finished()
                else:
                    if value == True:
                        doc.add(u'%s'%key)
                    elif value == False:
                        doc.add(u'NOT %s'%key)
                    else:
                        if type(value) is bson.binary.Binary:
                            doc.add(u"%s:%s"%(str(key), value.encode('hex')))
                        else:
                            doc.add(u"%s:%s"%(str(key), str(value)))

        def find_ACE(node):
            ace=list()
            id_sd = node.get('nTSecurityDescriptor')
            sd = self.sd_table.find({"sd_id":id_sd}).limit(1)[0]
            return sd

        l_l = doc.create_list("Node information")

        try:
            steps=options.cn.split(":")
            the_node=None
            nodes = self.datatable.find({"name":steps[-1]})
            for node in nodes:
                ancestors=find_parents(node)
                #print "I compare %s to %s"%(["$ROOT_OBJECT$"]+steps,[a['name'].rstrip() for a in ancestors])
                if ["$ROOT_OBJECT$\x00"]+steps == [a['name'] for a in ancestors]:
                    the_node=node
                    break
            l_l.add("Node '%s' security descriptor %s DNT_col: %s" % (the_node['name'], the_node.get('nTSecurityDescriptor'), the_node.get('DNT_col')))
            l_l.finished()
        except:
            l_l.add("No such node %s"%options.cn)
            l_l.finished()
            return

        # Displaying dinstinguish name
        l_m = doc.create_list("Distinguished name")
        dn = self.dnames.find({"DNT_col":node['DNT_col']}).limit(1)[0]
        l_m.add(dn['DName'])
        l_m.finished()
    
        # Displaying Siblings
        def display_siblings(node, l_n, recursive):
            siblings=find_siblings(node)
            if recursive!=0:
                for s in siblings:
                    if len(find_siblings(s))==0 or recursive==1:
                        l_n.add(u"%s"%s['name'])
                    else:
                        l_m=l_n.create_list(s['name'])
                        display_siblings(s, l_m, recursive-1)
                        l_m.finished()
            #if len(siblings)==0:
            #    for n in sorted([ str(s['name']) for s in siblings], key=str.lower):
            #        l_n.add(n)

        l_n = doc.create_list("Siblings")
        display_siblings(the_node, l_n, recursive=int(options.rec))
        l_n.finished()


        if options.ace:
        # Displaying ACE
            acl = find_ACE(node) 
            l_n=doc.create_list("ACEs") 
            pretty(acl, l_n)
            l_n.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "name")
        self.assert_field_exists(self.datatable, "Ancestors_col")
        self.assert_field_type(self.datatable, "name", str, unicode)
