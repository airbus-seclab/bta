from bta.miners import Miner

@Miner.register
class DNGrep(Miner):
    _name_ = "DNGrep"
    _desc_ = "DN grepper"
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--cn", help="Look for objects with given CN and print their DN")
    
    def run(self, options, doc):
        doc.add("Listing DN of all objects whose CN matches [%s]" % options.cn)

        l = doc.create_list("List of CN")
        def find_dn(r):
            if not r:
                return ""
            cn = r.get("cn") or r.get("name")
            if cn is None or cn=="$ROOT_OBJECT$":
                return ""
            r2 = self.datatable.find_one({"RecId":r["ParentRecId"]})
            return find_dn(r2)+"."+cn
    
        c = self.datatable.find({"cn":options.cn})
        for r in c:
            l.add("%s: %s" % (r.get("cn"),find_dn(r)))
        l.finished()
