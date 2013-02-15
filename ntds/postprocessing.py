#! /usr/bin/env python
import types
import ntds.backend.mongo


class PostProcessing(object):
    def __init__(self, options):
        self.options = options
        self.backend = options.backend
        self.dt = self.backend.open_table("datatable")

    def list_post_processors(self):
        return [pname for pname,proc in self.__class__.__dict__.iteritems()
                if type(proc) is types.FunctionType and pname.startswith("postproc_")]

    def post_process_all(self):
        for pname in self.list_post_processors():
            print "Post-processiong: %s" % pname
            self.post_process_one(pname)

    def post_process_one(self, name):
        proc = getattr(self, name)
        proc()

    def postproc_domains(self):
        domains = self.options.backend.open_table("domains")
        domains.create()
        domains.create_index("domain")
        domains.create_index("sid")

        def find_dn(r):
            if not r:
                return ""
            cn = r.get("cn") or r.get("name")
            if cn is None or cn=="$ROOT_OBJECT$":
                return ""
            r2 = self.dt.find_one({"RecId":r["ParentRecId"]})
            return find_dn(r2)+"."+cn


        for r in self.dt.find({"objectCategory":"2370", "objectSid":{"$exists":True}}):
            domains.insert({"domain":find_dn(r), "sid":r["objectSid"]})


def main():
    import optparse
    parser = optparse.OptionParser()
    
    parser.add_option("-C", dest="connection",
                      help="Backend connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    parser.add_option("-B", dest="backend_class", default="mongo",
                      help="database backend (amongst: %s)" % (", ".join(ntds.backend.Backend.backends.keys())))

    parser.add_option("--overwrite", dest="overwrite", action="store_true",
                      help="Delete tables that already exist in db")
    
    options, args = parser.parse_args()
    
    if options.connection is None:
        parser.error("Missing connection string (-C)")
    

    backend_class = ntds.backend.Backend.get_backend(options.backend_class)
    options.backend = backend_class(options)
    

    pp = PostProcessing(options)
    pp.post_process_all()

    

if __name__ == "__main__":
    main()
