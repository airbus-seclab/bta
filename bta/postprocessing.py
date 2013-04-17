#! /usr/bin/env python
import types
import bta.backend.mongo
import tools
import logging
log = logging.getLogger("bta.postprocessing")


class PostProcRegistry(tools.Registry):
    pass

class PostProcessing(object):
    def __init__(self, options):
        self.options = options
        self.backend = options.backend
        self.dt = self.backend.open_table("datatable")

    @classmethod
    def list_post_processors(cls):
        return list(PostProcRegistry.iterkeys())

    def post_process_all(self):
        alln = self.list_post_processors()
        done=set()
        while alln:
            k = alln.pop(0)
            dep = PostProcRegistry.get(k).get("depends",set())
            if dep.issubset(done):
                done.add(k)
                self.post_process_one(k)
            else:
                alln.append(k)

    def post_process_one(self, name):
        log.info("Post-processing: %s" % name)
        self.options.dblog.update_entry("Post-processing: %s" % name)
        proc = getattr(self, name)
        proc()

    @PostProcRegistry.register()
    def category(self):
        category = self.options.backend.open_table("category")
        category.create()
        category.create_index("id")
        category.create_index("name")

        idSchemaRec = self.dt.find_one({"cn": "Class-Schema"})
        if idSchemaRec is None:
            log.warning("No schema id found in datatable for category post processing")
            return
        idSchema = idSchemaRec['RecId']
        print idSchema
        for r in self.dt.find({"objectCategory": idSchema}):
            category.insert({"id":r["RecId"], "name":r["cn"]})
        
    @PostProcRegistry.register(depends={"category"})
    def domains(self):
        domains = self.options.backend.open_table("domains")
        domains.create()
        domains.create_index("domain")
        domains.create_index("sid")

        ct = self.options.backend.open_table("category")
        domRec = ct.find_one({"name": "Domain-DNS"})
        if domRec is None:
            log.warning("No domain dns found in datatable for domains post processing")
            return
        dom = domRec["id"]
        def find_dn(r):
            if not r:
                return ""
            cn = r.get("cn") or r.get("name")
            if cn is None or cn=="$ROOT_OBJECT$":
                return ""
            r2 = self.dt.find_one({"RecId":r["ParentRecId"]})
            return find_dn(r2)+"."+cn


        for r in self.dt.find({"objectCategory":dom, "objectSid":{"$exists":True}}):
            domains.insert({"domain":find_dn(r), "sid":r["objectSid"]})

    @PostProcRegistry.register()
    def usersid(self):
        usersid = self.options.backend.open_table("usersid")
        usersid.create()
        usersid.create_index("name")
        usersid.create_index("sid")
        usersid.create_index("account")

        ct = self.options.backend.open_table("category")
        persRec = ct.find_one({"name": "Person"})
        if persRec is None:
            log.warning("No name=Person entry found in datatable for usersid post processing")
            return
        pers = persRec['id']
        for r in self.dt.find({"objectCategory":pers, "objectSid":{"$exists":True}}):
            usersid.insert({"name":r["name"], "account":r["sAMAccountName"], "sid": r["objectSid"]})


def main():
    import optparse
    parser = optparse.OptionParser()
    
    parser.add_option("-C", dest="connection",
                      help="Backend connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    parser.add_option("-B", dest="backend_class", default="mongo",
                      help="database backend (amongst: %s)" % (", ".join(bta.backend.Backend.backends.keys())))

    parser.add_option("--only", dest="only", metavar="POSTPROC",
                      help="Only run POSTPROC (amongst %s)" % (", ".join(PostProcessing.list_post_processors())))

    parser.add_option("--overwrite", dest="overwrite", action="store_true",
                      help="Delete tables that already exist in db")
    
    options, args = parser.parse_args()
    
    if options.connection is None:
        parser.error("Missing connection string (-C)")
    

    backend_class = bta.backend.Backend.get_backend(options.backend_class)
    options.backend = backend_class(options)
    

    pp = PostProcessing(options)
    if options.only:
        pp.post_process_one(options.only)
    else:
        pp.post_process_all()
    options.backend.commit()
    

if __name__ == "__main__":
    main()
