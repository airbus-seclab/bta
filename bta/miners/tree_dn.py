# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
from struct import unpack_from
from base64 import b64decode

@Miner.register
class DNTree(Miner):
    _name_ = "DNTree"
    _desc_ = "DN Tree"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--cn", help="Look for objects with given CN and print their DN")
    
    def run(self, options, doc):
        doc.add("Display the tree of all objects in the database")

        l = doc.create_list("List of objects")

	def find_parents(node):
		parents=list()
		ancestors = node['Ancestors_col']
		nb_ancestors = len(ancestors.encode('hex'))/8
		id_ancestors = unpack_from('i'*nb_ancestors,ancestors)
		for a in id_ancestors:
			parents.append(self.datatable.find({"DNT_col":a}).limit(1)[0])
		return parents

	def find_siblings(node):
		siblings=list()
		id_siblings=[s["DNT_col"] for s in self.datatable.find({"PDNT_col":node['DNT_col']},{"DNT_col":1})]
		for i in id_siblings:
			siblings.append(self.datatable.find({"DNT_col":i}).limit(1)[0])

		return siblings


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
		the_node['name']	
	except:
		l.add("No such node %s"%options.cn)
		l.finished()
		return



	l.add("Ancectors:")
	ancestors=find_parents(the_node)
	l.add("/".join([a['name'] for a in ancestors]))

	l.add("\n\nSiblings:")
	siblings=find_siblings(the_node)
	l.add("\n".join([s['name'] for s in siblings]))
        
        l.finished()
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "name")
        self.assert_field_exists(self.datatable, "Ancestors_col")
        self.assert_field_type(self.datatable, "name", str, unicode)
