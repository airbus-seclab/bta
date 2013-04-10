from bta.miners import Miner


@Miner.register
class Skel(Miner):
    _name_ = "skeleton"
    _desc_ = "skeleton, list SD id and hashes when id < 50"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--dummy", help="dummy option")
        parser.add_argument("--dummy_flag", help="dummy flag", action="store_true")
    
    def run(self, options, doc):
        doc.add("Option dummy is %s" % options.dummy)

        table = doc.create_table("my table")
        table.add(["id","hash"])
        table.add()

        for r in self.sd_table.find({"id": {"$lt":50}}):
            table.add([r["id"],r["hash"]])
            
        table.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        assert self.datatable.find({"cn":{"$exists":True}}).count() > 10, "less than 10 cn in datatable"

