# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
from datetime import datetime, timedelta
from bta.miners.tools import Family
import re

@Miner.register
class SchemaModifs(Miner):
    _name_ = "SchemaModifs"
    _desc_ = "Display all schema modification over the time"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--dn', help='Schema Partition Distinghuish name')
   
    def run(self, options, doc):
        if not options.dn:
            print "the schema partition distinguish name is mandatory"
            exit(1)
        the_node=Family.find_the_one(options.dn, self.datatable)
        t = doc.create_list("All changes in the schema partition %s are" % options.dn)
        #print Family.find_offspring(the_node,self.datatable,-1,['name', 'DNT_col', 'replPropertyMetaData'])
        print "All dates of changes are:"
        dates = self.datatable.find({"Ancestors_col":{"$in":[the_node["DNT_col"]]}}).distinct("replPropertyMetaData.date")
        #for date in dates:
            #print "-> %s"%date
            #req = {"$and":[{"replPropertyMetaData.date":{"$in":[date]}},{"Ancestors_col":{"$in":[the_node["DNT_col"]]}}]}
            #filters = {"replPropertyMetaData.date":1,"replPropertyMetaData.OID":1,"name":1}
            #print req
            #print "[%s]"%self.datatable.find(req, filters).count()
        for date in dates:
            print "-> %s"%date
            #Get details for all dates
            modified_objects = self.datatable.find({"$and":[{"replPropertyMetaData.date":{"$in":[date]}},
                                                            {"Ancestors_col":{"$in":[the_node["DNT_col"]]}}
                                                           ]
                                                   },
                                                   {"replPropertyMetaData.date":1,
                                                    "replPropertyMetaData.OID":1,
                                                    "name":1})
            for m in modified_objects:
                print "\t",m["name"]
                for att in m["replPropertyMetaData"]:
                    if att["date"]==date:
                        convetion=self.guid.find_one({"id":att["OID"]})["name"] if self.guid.find_one({"id":att["OID"]}) else att["OID"]
                        print "\t\t",att["date"],":",convetion
        t.flush()
        t.finished()
        
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "dn", str, unicode)
