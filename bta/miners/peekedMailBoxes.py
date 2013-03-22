from bta.miners import Miner
from collections import defaultdict

SDTABLE="sdtable"
DATATABLE="datatable"


@Miner.register
class PeekedMailboxes(Miner):
    _name_ = "peekedMailBoxes"
    _desc_ = "List mailboxes whose owner has no exclusive access to"

    def get_sid(self, sid):
        objlist = self.dt.find({'objectSid': sid})
        for obj in objlist:
            if 'cn' in obj: return obj['cn']

    def getSecurityDescriptor(self, sdId):
        sd = self.sd.find({'id': sdId})
        aces = []
        for ace in sd:
            try:
                acl = ace['value']["DACL"]["ACEList"]
                for truc in acl:
                    if truc['SID'] == 'S-1-5-10': # myself
                        continue
                    truc['SID'] = self.get_sid(truc['SID'])
                    aces.append(truc)
            except Exception, e:
                pass
        return aces

    def run(self, options, doc):
        self.dt = options.backend.open_table("datatable")
        self.sd = options.backend.open_table("sdtable")

        userAccess = {}     # Permissions per User
        mailboxAccess = {}  # Permissions per mailbox

        mailboxes=self.dt.find({"msExchMailboxSecurityDescriptor": {"$exists":True}}, {"msExchMailboxSecurityDescriptor": True, "cn": True})
        for mbox in mailboxes:
            userMailboxCN = mbox['cn']
            userMailBoxSecurityDescriptor = mbox['msExchMailboxSecurityDescriptor']
            aces = self.getSecurityDescriptor(userMailBoxSecurityDescriptor)
            if not aces:
                continue
            for ace in aces:
                rules=[]
                for key,val in ace['AccessMask'].items():
                    if not val:
                        continue
                    rules.append("+%s" % key)

                mailboxAccess[userMailboxCN] = mailboxAccess.get(userMailboxCN, {})
                mailboxAccess[userMailboxCN][ace['SID']] = ', '.join(rules)
                for rule in rules:
                   userAccess[ace['SID']] =  userAccess.get(ace['SID'], {})
                   userAccess[ace['SID']][userMailboxCN] = rules

        s1 = doc.create_subsection("Who has access to this mailbox?")
        table = s1.create_table("")
        for k,v in mailboxAccess.items():
            table.add([k, ' '.join(map(lambda b: '{%s %s}' % (b[0],b[1]), v.items()))])
        table.finished()
        s1.finished()
        
        s2 = doc.create_subsection("Which mailbox can be accessed by this user?")
        table = s2.create_table("")

        for k,v in userAccess.items():
            table.add([k,  ' '.join(map(lambda b: '{%s %s}' % (b[0],b[1]), v.items()))])
        table.finished()
        s2.finished()

