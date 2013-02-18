#! /usr/bin/env python
import types
import ntds.backend.mongo

import logging
log = logging.getLogger("bta.postprocessing")

class PostProcessing(object):
    PREFIX="postproc_"
    def __init__(self, options):
        self.options = options
        self.backend = options.backend
        self.dt = self.backend.open_table("datatable")

    @classmethod
    def list_post_processors(cls):
        return [pname[len(cls.PREFIX):] for pname,proc in cls.__dict__.iteritems()
                if type(proc) is types.FunctionType and pname.startswith(cls.PREFIX)]

    def post_process_all(self):
        for pname in self.list_post_processors():
            log.info("Post-processiong: %s" % pname)
            self.post_process_one(pname)

    def post_process_one(self, name):
        if not name.startswith(self.PREFIX):
            name = self.PREFIX+name
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

    def postproc_usersid(self):
        usersid = self.options.backend.open_table("usersid")
        usersid.create()
        usersid.create_index("name")
        usersid.create_index("sid")
        usersid.create_index("account")

        for r in self.dt.find({"objectCategory":"3818", "objectSid":{"$exists":True}}):
            usersid.insert({"name":r["name"], "account":r["sAMAccountName"], "sid": r["objectSid"]})


def main():
    import optparse
    parser = optparse.OptionParser()
    
    parser.add_option("-C", dest="connection",
                      help="Backend connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    parser.add_option("-B", dest="backend_class", default="mongo",
                      help="database backend (amongst: %s)" % (", ".join(ntds.backend.Backend.backends.keys())))

    parser.add_option("--only", dest="only", metavar="POSTPROC",
                      help="Only run POSTPROC (amongst %s)" % (", ".join(PostProcessing.list_post_processors())))

    parser.add_option("--overwrite", dest="overwrite", action="store_true",
                      help="Delete tables that already exist in db")
    
    options, args = parser.parse_args()
    
    if options.connection is None:
        parser.error("Missing connection string (-C)")
    

    backend_class = ntds.backend.Backend.get_backend(options.backend_class)
    options.backend = backend_class(options)
    

    pp = PostProcessing(options)
    if options.only:
        pp.post_process_one(options.only)
    else:
        pp.post_process_all()

    

if __name__ == "__main__":
    main()
