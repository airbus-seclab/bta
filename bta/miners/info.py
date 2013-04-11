from bta.miners import Miner


@Miner.register
class Info(Miner):
    _name_ = "info"
    _desc_ = "Informations about AD tables"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("-v", "--verbose", help="verbose output", action="store_true")
    
    def run(self, options, doc):
        tbl = doc.create_table("datatable")
        tbl.add(("number of records", self.datatable.count()))
        tbl.add(("number of columns", self.datatable_meta.count()))
        tbl.finished()
        tbl = doc.create_table("sd_table")
        tbl.add(("number of records", self.sd_table.count()))
        tbl.finished()
        tbl = doc.create_table("linktable")
        tbl.add(("number of records", self.linktable.count()))
        tbl.finished()

        if options.verbose:
            tbl = doc.create_table("datatable columns")
            tbl.add(("name", "attname", "type", "number of records"))
            tbl.add()
            for r in self.datatable_meta.find():
                tbl.add((r["name"], r["attname"], r["type"],r["count"] ))
            tbl.finished()
        
        if options.verbose:
            tbl = doc.create_table("categories")
            tbl.add(("id", "name", "number of records"))
            tbl.add()
            for r in self.category.find():
                tbl.add((r["id"], r["name"], self.datatable.find({"objectCategory": str(r["id"])}).count()))
            tbl.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        Miner.assert_field_exists(self.datatable,"objectCategory")
        Miner.assert_field_type(self.datatable,"objectCategory", str, unicode)
