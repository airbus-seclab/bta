#! /usr/bin/env python

# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from collections import defaultdict
import bta.backend
import bta.dblog
import bta.tools.registry
import logging
log = logging.getLogger("bta.postprocessing")


class PostProcRegistry(bta.tools.registry.Registry):
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
        self.options.dblog.update_entry("Start Post-processor: %s" % name)
        proc = getattr(self, name)
        proc()
        self.options.dblog.update_entry("End Post-processor: %s" % name)

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
        idSchema = idSchemaRec['DNT_col']
        for r in self.dt.find({"objectCategory": idSchema}):
            category.insert({"id":r["DNT_col"], "name":r["cn"]})

    @PostProcRegistry.register()
    def rightsGuids(self):
        guid = self.options.backend.open_table("guid")
        guid.create()
        guid.create_index("id")
        guid.create_index("name")
        # guid for schema
        for id_ in self.dt.find({"schemaIDGUID": {"$exists": 1}}):
            guid.insert({"id":id_["schemaIDGUID"].lower(), "name":id_["name"]})
        # guid for object
        for id_ in self.dt.find({"objectGUID": {"$exists": 1}}):
            guid.insert({"id":id_["objectGUID"].lower(), "name":id_["name"]})
        #guid for rights
        for id_ in self.dt.find({"rightsGuid": {"$exists": 1}}):
            guid.insert({"id":id_["rightsGuid"].lower(), "name":id_["name"]})
        #ObjectId
        for id_ in self.dt.find({"objectSid": {"$exists": 1}}):
            guid.insert({"id":id_["objectSid"].lower(), "name":id_["name"]})
        #
        for id_ in self.dt.find({"attributeID": {"$exists": 1}}):
            guid.insert({"id":id_["attributeID"].lower(), "name":id_["name"]})

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
            r2 = self.dt.find_one({"DNT_col":r.get("PDNT_col")})
            if not r2:
                return ""
            return find_dn(r2)+"."+cn


        for r in self.dt.find({"objectCategory":dom, "objectSid":{"$exists":True}}):
            domains.insert({"domain":find_dn(r), "sid":r["objectSid"]})

    @PostProcRegistry.register()
    def dnames(self):
        dnames = self.options.backend.open_table("dnames")
        dnames.create()
        dnames.create_index("name")
        dnames.create_index("DNT_col")
        dnames.create_index("DName")

        error = 0
        for r in self.dt.find({"Ancestors_col":{"$exists":True}}):
            dn=list()
            for p in r["Ancestors_col"]:
                try:
                    p=self.dt.find({"DNT_col":p}).limit(1)[0]
                except:
                    error += 1
                    continue
                if p.get('name')=="$ROOT_OBJECT$\x00":
                    continue
                if p.get('dc'):
                    dn.append("DC=%s"%p['name'])
                elif p.get('cn'):
                    dn.append("CN=%s"%p['name'])
                elif p.get('name'):
                    dn.append("DC=%s"%p['name'])
            dn.reverse()
            dnames.insert({"name":r["name"], "DNT_col":r["DNT_col"], "DName":",".join(dn)})
        if error:
            log.warning("Encoutered %i errors during distinguished name resolution")


    @PostProcRegistry.register(depends={"dnames"})
    def memberOf(self):
        memberOf = self.options.backend.open_table("memberOf")
        memberOf.create()
        memberOf.create_index("member_DNT")
        memberOf.create_index("member_name")
        memberOf.create_index("member_dn")
        memberOf.create_index("group_DNT")
        memberOf.create_index("group_names")
        memberOf.create_index("group_dn")

        dt = self.options.backend.open_table("datatable")
        lt = self.options.backend.open_table("link_table")
        dnames = self.options.backend.open_table("dnames")

        def get_group_name(DNT):
            return

        members = defaultdict(list)
        for res in lt.find({}, {"link_DNT":True, "backlink_DNT":True}):
            members[res["backlink_DNT"]].append(res["link_DNT"])

        for member_DNT,groups_DNT in members.iteritems():
            member_name_dn = dnames.find_one({"DNT_col": member_DNT})
            group_names_dn = [ dnames.find_one({"DNT_col": DNT}) for DNT in groups_DNT ]
            group_dn = [x["DName"] for x in group_names_dn]
            group_names = [x["name"] for x in group_names_dn]
            memberOf.insert({"member_DNT": member_DNT, "member_name": member_name_dn["name"], 
                               "member_dn":member_name_dn["DName"], 
                               "groups": groups_DNT, "group_dn": group_dn, "group_names": group_names})


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

    @PostProcRegistry.register()
    def oid(self):
        """
        Cache class oid names
        (ex. "1.2.840.113556.1.5.8" -> "group")
        """
        oid = self.options.backend.open_table("oid")
        oid.create()
        oid.create_index("oid")
        oid.create_index("name")

        ct = self.options.backend.open_table("category")
        classSchRec = ct.find_one({"name": "Class-Schema"})
        if classSchRec is None:
            log.warning("No name=Class-Schema entry found in datatable for class OID processing")
            return
        classSch = classSchRec["id"]
        for r in self.dt.find({"objectCategory": classSch, "governsID": {"$exists": True}}, {"cn": True, "governsID": True}):
            oid.insert({"name": r["cn"], "oid": r["governsID"]})

    @PostProcRegistry.register()
    def linkID(self):
        """
        Cache link ID names
        Link base can be obtained from linkID (linkID << 1 == link base)
        even linkID are forward links, odd linkID are backlinks
        back_link = forward_link + 1
        base_link = (back_link << 1) == (forward_link << 1)

        (ex. "1" -> "Member")
        """
        linkid = self.options.backend.open_table("linkid")
        linkid.create()
        linkid.create_index("linkid")
        linkid.create_index("name")

        ct = self.options.backend.open_table("category")
        attrSchRec = ct.find_one({"name": "Attribute-Schema"})
        if attrSchRec is None:
            log.warning("No name=Class-Schema entry found in datatable for class OID processing")
            return
        attrSch = attrSchRec["id"]
        cachedLinkIDs = set()
        for r in self.dt.find({"objectCategory": attrSch, "linkID": {"$exists": True}}, {"linkID": True, "cn": True}):
            cachedLinkIDs.add(r["linkID"])
            linkid.insert({"name": r["cn"], "linkid": r["linkID"]})
        for i in sorted(cachedLinkIDs):
            if i^1 not in cachedLinkIDs:
                # insert missing associated link
                res = linkid.find_one({"linkid": i})
                linkid.insert({"name": res["name"] + " (reverse link)", "linkid": i^1})

def main():
    import argparse
    
    bta.backend.import_all()

    parser = argparse.ArgumentParser()

    parser.add_argument("-C", dest="connection",
                        help="Backend connection string. Ex: 'dbname=test user=john' for PostgreSQL or '[ip]:[port]:dbname' for mongo)", metavar="CNX")
    parser.add_argument("-B", dest="backend_class", default="mongo",
                        help="database backend", choices=bta.backend.Backend.backends.keys())
    
    parser.add_argument("--only", dest="only",
                        help="Only run POSTPROC", choices=PostProcessing.list_post_processors())
    
    parser.add_argument("--overwrite", dest="overwrite", action="store_true",
                        help="Delete tables that already exist in db")

    options, _args = parser.parse_args()

    if options.connection is None:
        parser.error("Missing connection string (-C)")

    backend_class = bta.backend.Backend.get_backend(options.backend_class)
    options.backend = backend_class(options)

    with bta.dblog.DBLogEntry.dblog_context(options.backend) as options.dblog:

        pp = PostProcessing(options)
        if options.only:
            pp.post_process_one(options.only)
        else:
            pp.post_process_all()
        options.backend.commit()


if __name__ == "__main__":
    main()
