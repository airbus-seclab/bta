# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner


@Miner.register
class MapLinks(Miner):
    _name_ = "MapLinks"
    _desc_ = "List (link type, linked object type, backlinked object type) from link_table"
    _uses_ = ['raw.datatable', 'raw.link_table', 'raw.linkid']
    class_cache = dict()

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--output-format', choices=['dot', 'table'], help='Output format', default='table')

    def run(self, options, doc):
        self.options = options

        relationTypes = set()

        links = self.link_table.find()
        for link in links:
            # fetch related objects info
            linkedObj = self.datatable.find_one({"DNT_col": link["link_DNT"]})
            linkedObjType = self.get_objectClass_name(linkedObj['objectClass'][0])

            backlinkedObj = self.datatable.find_one({"DNT_col": link["backlink_DNT"]})
            backlinkedObjType = self.get_objectClass_name(backlinkedObj['objectClass'][0])

            linkType = self.linkid.find_one({'linkid': link['link_base']*2})['name']
            relationTypes.add((linkedObjType, linkType, backlinkedObjType))

        if options.output_format == 'table':
            table = doc.create_table("List of link types and associated object categories and classes")
            table.add(("Linked object class", "Link type", "Backlinked object class"))
            for t in relationTypes:
                table.add(t)
            table.finished()
        elif options.output_format == 'dot':
            dot = 'digraph relations {\n'
            for l, t, b in relationTypes:
                dot += '"%s" -> "%s" [ label = "%s" ];\n' % (b, l, t)
            dot += '}'
            doc.add(dot)

    def get_objectClass_name(self, oc):
        """ Cache object class to class name mapping """
        r = MapLinks.class_cache.get(oc)
        if r:
            return r
        r = self.datatable.find_one({'governsID': oc})['name']
        MapLinks.class_cache[oc] = r
        return r

    def assert_consistency(self):
        Miner.assert_consistency(self)
        assert self.linkid.find({"name": {"$exists": True}}).count() > 10, "less than 10 names in linkid table"
