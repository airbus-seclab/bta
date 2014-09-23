# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from collections import defaultdict


@Miner.register
class ListDomain(Miner):
    _name_ = "ListDomain"
    _desc_ = "List domains"
    _uses_ = ["raw.datatable"]

    def traverse(self, nameprefix, dnt):
        """
        Recursively reach leaves of the tree, recording traversal path.
        Outputs traversal path (full domain).
        """
        result = set()
        children = self.domain_children[dnt]
        if not children:
            # Leave has been reached
            result.add(nameprefix + "." + self.domain_names[dnt])
        else:
            for child in children:
                name = self.domain_names[dnt]
                suffix = "." + self.domain_names[dnt]
                if name == "$ROOT_OBJECT$\x00":
                    suffix = ""
                result |= self.traverse(nameprefix + suffix, child)
        return result

    def run(self, options, doc):

        match = {'objectClass': '1.2.840.113556.1.5.66'}  # "Domain" objects

        # parent DNT_col (PDNT_col) -> set(child DNT_col) mapping
        self.domain_children = defaultdict(set)

        # DNT_col -> name mapping
        self.domain_names = dict()

        # Recursively find members of matching groups.
        for domain in self.datatable.find(match):
            self.domain_children[domain['PDNT_col']].add(domain['DNT_col'])
            self.domain_names[domain['DNT_col']] = domain['name']
        # Find all non-domain parents and their names
        dntlist = set(self.domain_children.keys())
        while dntlist:
            dnt = dntlist.pop()
            if dnt not in self.domain_names:
                parent = self.datatable.find_one({'DNT_col': dnt})
                parentname = parent['name']
                self.domain_names[parent['DNT_col']] = parentname
                if parentname != '$ROOT_OBJECT$\x00':
                    self.domain_children[parent['PDNT_col']].add(dnt)
                    dntlist.add(parent['PDNT_col'])
        # Start from $ROOT_OBJECT$
        dnt = (k for k,v in self.domain_names.items() if v=='$ROOT_OBJECT$\x00').next()
        doc.add("List of domains")
        for domain in sorted(list(self.traverse("", dnt))):
            doc.add(domain)

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "DNT_col", int)
        self.assert_field_type(self.datatable, "PDNT_col", int)
        self.assert_field_type(self.datatable, "name", str, unicode)
