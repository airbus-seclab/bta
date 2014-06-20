# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.tools.mtools import Family
from bta.tools.WellKnownSID import SID2StringFull

@Miner.register
class SchemaModifs(Miner):
    _name_ = "SchemaModifs"
    _desc_ = "Display all schema modification over the time"
    _uses_ = [ "raw.datatable", "raw.sd_table", "raw.guid" ]

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--dn', help='Schema Partition Distinghuish name')
        parser.add_argument('--changes', action="store_true", help='Schema Partition changes')
        parser.add_argument("--owner", action="store_true", help="List owners of Schema objects")
        parser.add_argument("--version", action="store_true", help="List owners of Schema objects")

    def extract_dates(self, doc, dn, the_node):
        t = doc.create_list("All changes in the schema partition %s are" % dn)
        u = t.create_list("All dates of changes are:")
        dates = self.datatable.find({"Ancestors_col":{"$in":[the_node["DNT_col"]]}}).distinct("replPropertyMetaData.date")

        for date in dates:
            u.add("%s"%date)
        u.flush()
        u.finished()

        for date in dates:
            #Get details for all dates
            l = t.create_list("%s"%date)
            modified_objects = self.datatable.find({"$and":[{"replPropertyMetaData.date":{"$in":[date]}},
                                                            {"Ancestors_col":{"$in":[the_node["DNT_col"]]}}
                                                           ]
                                                   },
                                                   {"replPropertyMetaData.date":1,
                                                    "replPropertyMetaData.OID":1,
                                                    "name":1})
            for m in modified_objects:
                ll = l.create_list(m["name"])
                for att in m["replPropertyMetaData"]:
                    if att["date"]==date:
                        convetion=self.guid.find_one({"id":att["OID"]})["name"] if self.guid.find_one({"id":att["OID"]}) else att["OID"]
                        ll.add("%s:%s"%(att["date"],convetion))
        t.flush()
        t.finished()
        return t

    def extract_owner(self, doc, the_node):
        owners = dict()
        req = {"Ancestors_col":{"$in":[the_node["DNT_col"]]}}
        schema_objects = self.datatable.find(req)

        for obj in schema_objects:
            owner_name = SID2StringFull(self.sd_table.find_one({"sd_id":int(obj["nTSecurityDescriptor"])},{"sd_value.Owner":1})["sd_value"]["Owner"], self.guid)
            if not owners.has_key(owner_name):
                owners[owner_name]=[obj["name"]]
            else:
                owners[owner_name].append(obj["name"])

        for owner, objs in owners.items():
            t = doc.create_list("%s Owns the following objects" % owner)
            for o in objs:
                t.add(o)
            t.flush()
            t.finished()

    def extract_version(self, doc, the_node):
        t = doc.create_list("The schema version is Version")
        t.add("%s"%the_node["objectVersion"])
        t.flush()
        t.finished()

    def run(self, options, doc):
        if not options.dn:
            print "the schema partition distinguish name is mandatory"
            exit(1)
        the_node=Family.find_the_one(options.dn, self.datatable)

        if options.changes:
            self.extract_dates(doc, options.dn, the_node)

        if options.owner:
            self.extract_owner(doc, the_node)

        if options.version:
            self.extract_version(doc, the_node)

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "dn", str, unicode)
