# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

import os
import ldap
from bta.backend import Backend, VirtualTable, SpecialTable
import bta.tools.expr

import logging
log = logging.getLogger("bta.backend.ldap")

@Backend.register("ldap")
class LDAPBackend(Backend):
    def __init__(self, options, connection=None):
        Backend.__init__(self, options, connection)
        self.cnx=ldap.initialize(self.connection)
        self.user = os.getenv("BTA_LDAP_USER")
        self.passwd = os.getenv("BTA_LDAP_PASS")
        self.cnx.simple_bind_s(self.user, self.passwd)

    def open_virtual_table(self, name):
        if name == "datasd":
            return LDAPVirtualDataSD(self.options, self, name)

    def open_special_table(self, name):
        if name == "categories":
            return LDAPCategories()


class LDAPCategories(SpecialTable):
    person = "CN=Person*"
    computer = "CN=Computer*"
    def assert_consistency(self):
        pass

#    def count(self, name):
#        # XXX should be > 0 if cnx working. Being > 0 should be the only thing that counts
#        return len(self.cnx.search_s('',ldap.SCOPE_SUBTREE, '(cn=subschema)',['*','+']))
#    def find(self, name, *args, **kargs):
#        return {}
#    def find_one(self, name, *args, **kargs):
#        return {}
#



class LDAPVirtualDataSD(VirtualTable):
    def __init__(self, options, backend, name):
        VirtualTable.__init__(self, options, backend, name)
    def find(self, *args, **kargs):
        self.db.find(self.name, *args, **kargs)
    def assert_consistency(self):
        pass
    
