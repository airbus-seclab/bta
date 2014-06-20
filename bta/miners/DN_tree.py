# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.tools.mtools import Family
import bson.binary

@Miner.register
class DNTree(Miner):
    _name_ = "DNTree"
    _desc_ = "DN Tree"
    _uses_ = [ "raw.datatable", "raw.sd_table", "raw.guid", "raw.dnames" ]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--cn", help="Look for objects with given CN and print their DN")
        parser.add_argument("--rec", help="Recursive search deapth (-1 = infinite)")
        parser.add_argument("--ace", help="Display ACEs")

    def run(self, options, doc):
        doc.add("Display the tree of all objects in the database")

        # Displaying Siblings
        def display_childs(node, l_n, recursive):
            childs=Family.find_childs(node, self.datatable)
            if recursive!=0:
                for s in childs:
                    if len(Family.find_childs(s, self.datatable))==0 or recursive==1:
                        l_n.add(u"%s"%s['name'])
                    else:
                        l_m=l_n.create_list(s['name'])
                        display_childs(s, l_m, recursive-1)
                        l_m.finished()

        # Display all value nicely (human readable)
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
                        continue
                    #    doc.add(u'NOT %s'%key)
                    else:
                        if type(value) is bson.binary.Binary:
                            doc.add(u"%s:%s"%(str(key), value.encode('hex')))
                        else:
                            if str(key) == "SID":
                                # Find object
                                c = self.datatable.find({"objectSid":str(value)},{"name":1,"PDNT_col":1})
                                good=c[0]
                                # If several choice we take the one under WellKnown Security Principals
                                if c.count()>1:
                                    #Wellknown security Principals id:
                                    WSP_id = self.datatable.find({"name":"WellKnown Security Principals"},{"DNT_col":1}).limit(1)[0].get('DNT_col')
                                    for o in c:
                                        if o.get('PDNT_col')==WSP_id:
                                            good=o
                                            break
                                doc.add(u"%s:%s (%s)"%(str(key), good.get('name'), str(value)))

                            elif str(key) == "ObjectType":
                                doc.add(u"%s:%s (%s)"%(str(key), self.guid.find({"id":str(value)},{"name":1}).limit(1)[0].get('name'), str(value)))
                            elif str(key) == "InheritedObjectType":
                                doc.add(u"%s:%s (%s)"%(str(key), self.guid.find({"id":str(value)},{"name":1}).limit(1)[0].get('name'), str(value)))
                            else:
                                doc.add(u"%s:%s"%(str(key), str(value)))

        def find_ACE(node):
            id_sd = node.get('nTSecurityDescriptor')
            sd = self.sd_table.find({"sd_id":id_sd}).limit(1)[0]
            return sd

        l_l = doc.create_list("Node information")

        try:
            the_node=Family.find_the_one(options.cn, self.datatable)
            l_l.add("Node '%s' security descriptor %s DNT_col: %s" % (the_node['name'], the_node.get('nTSecurityDescriptor'), the_node.get('DNT_col')))
            l_l.finished()
        except Exception as e:
            l_l.add("No such node %s"%options.cn)
            l_l.finished()
            print e
            return

        # Displaying dinstinguish name
        l_m = doc.create_list("Distinguished name")
        dn = self.dnames.find({"DNT_col":the_node['DNT_col']}).limit(1)[0]
        l_m.add(dn['DName'])
        l_m.finished()


        depth = 1
        if options.rec:
            depth=int(options.rec)
        l_n = doc.create_list("Childs")
        display_childs(the_node, l_n, recursive=depth)
        l_n.finished()


        if options.ace:
        # Displaying ACE
            acl = find_ACE(the_node)
            l_n=doc.create_list("ACEs")
            pretty(acl, l_n)
            l_n.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "name")
        self.assert_field_exists(self.datatable, "Ancestors_col")
        self.assert_field_type(self.datatable, "name", str, unicode)
