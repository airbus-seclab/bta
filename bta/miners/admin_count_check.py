# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
from bta.miners import list_group

@Miner.register
class AdminCountCheck(Miner):
    _name_ = "AdminCountCheck"
    _desc_ = "list accounts that have admincount=1 but are not admin account"
    _uses_ = [ "raw.datatable", "raw.guid", "special.categories" ]

    def get_group_of(self, account):
        return self.guid.find_one({"id":account.get('objectGUID')}).get('name')

    def get_name_of(self, nodeSid):
        return self.datatable.find_one({"objectSid":nodeSid}).get("name")

    def run(self, options, doc):
        adminAccounts=["Schema Admins",
                       "Enterprise Admins",
                       "Domain Admins",
                       "Administrators",
                       "Server Operators",
                       "Account Operators",
                       "Print Operators",
                       "Backup Operators",
                       "Remote Desktop Users",
                       "Group Policy Creator Owners",
                       "Incoming Forest Trust Builders",
                       "Cert Publishers"]

        # Find all those account in the database
        adminAccountsObjects=list()
        for account in adminAccounts:
            match = {"$and": [{'objectCategory': self.categories.group},
                {"$or": [ { "name": { "$regex": account } },
                { "objectSid": { "$regex": account } }
                ]}]}

            l = self.datatable.find(match)
            for i in l:
                adminAccountsObjects.append(i)

        # Find all members of those account thanx to the miner ListGroup
        LGMiner=list_group.ListGroup(self.backend)
        adminAccountsMembers=list()
        for account in adminAccountsObjects:
            adminAccountsMembers+=LGMiner.get_members_of(account['objectSid'], True)
        adminAccountsMembersSid=[a for a,_,_,_ in adminAccountsMembers]
        # Find all accounts with adminCount=1
        accountsWithAdminCount=list()
        for a in self.datatable.find({'$and': [{'objectCategory': self.categories.person},{"adminCount":1}]}):
            accountsWithAdminCount.append(a)

        headers=['Account','Group', 'adminCount']
        t = doc.create_table("Members of %s"%", ".join(adminAccounts))
        t.add(headers)
        t.add()

        for account in accountsWithAdminCount:
            if not account.get('objectSid') in adminAccountsMembersSid:
                t.add(("%s (%s)"%(account.get('name'),account.get('objectSid')), self.get_group_of(account),account.get('adminCount')))
        t.finished()
