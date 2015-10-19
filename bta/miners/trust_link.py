# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner

@Miner.register
class TrustLink(Miner):
    _name_ = "TrustLink"
    _desc_ = "Find all trusted domain object"
    _uses_ = [ "raw.datatable", "special.categories" ]

    def run(self, options, doc):
        trusted = self.datatable.find({"objectCategory" : self.categories.trusted_domain})

        ta = doc.create_table("Trusted domains:")
        ta.add(["Partner","Created","Changed", "Direction", "type", "Attributes"])
        ta.add()
        for t in trusted:
            trustatt = t.get("trustAttributes")
            if trustatt is None:
                trustatt = {u'flags': {u'EMPTY': True}}
            ta.add([t.get("trustPartner"),
                    t.get("whenCreated"),
                    t.get("whenChanged"),
                    t.get("trustDirection"),
                    t.get("trustType"),
                    #", ".join([a for a,b in t.get("trustAttributes").get("flags").items() if b]) ])
                    ", ".join([a for a,b in trustatt.get("flags").items() if b]) ])
        ta.flush()
        ta.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_type(self.datatable, "name", str, unicode)
