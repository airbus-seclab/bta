# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.tools.mtools import Family

@Miner.register
class Domains(Miner):
    _name_ = "Domains"
    _desc_ = "Display Informations about domains"
    _uses_ = [ "raw.datatable" ]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--dn', help='Schema Partition Distinghuish name')

    def run(self, options, doc):
        if not options.dn:
            print "the schema partition distinguish name is mandatory"
            exit(1)
        the_node=Family.find_the_one(options.dn, self.datatable)
        partition=Family.find_the_one("%s:Configuration:Partitions"%options.dn, self.datatable)

        t = doc.create_list("The Domain Functional level of %s is" % options.dn)
        t.add("%s"%the_node["msDS_Behavior_Version"])
        t.flush()
        t.finished()

        u = doc.create_list("The Forest Functional level of %s is"%options.dn)
        u.add("%s"%partition["msDS_Behavior_Version"])
        u.flush()
        u.finished()

        return t


    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "dn", str, unicode)
