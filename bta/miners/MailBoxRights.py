from bta.miners import Miner
from collections import defaultdict
from bta.miners.tools import User, Group, Sid, Record

SDTABLE="sdtable"
DATATABLE="datatable"

@Miner.register
class MailBoxRights(Miner):
    _name_ = "MailBoxRights"
    _desc_ = "List of users whos access to a mailbox"

    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--user", help="Look user matching the SID", metavar="SID")
        parser.add_argument("--userid", help="Look user matching the samAccount", metavar="REGEX")

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
        userAccess = {}     # Permissions per User
        mailboxAccess = {}  # Permissions per mailbox

        if options.user:
            match =  { "objectSid": options.user }  
        else:
            if options.userid:
                match =  { "sAMAccountName": { "$regex" : options.userid } } 

        mailboxes=self.dt.find_one(match)
        for mbox in mailboxes:
            userMailboxCN = mailboxes['cn']
            userMailBoxSecurityDescriptor = mailboxes['msExchMailboxSecurityDescriptor']
            aces = self.getSecurityDescriptor(userMailBoxSecurityDescriptor)
            if not aces:
                continue
            for ace in aces:
                rules=[]
                for key,val in ace['AccessMask'].items():
                    if not val:
                        continue
                    rules.append("+%s" % key)

                for rule in rules:
                   userAccess[ace['SID']] =  userAccess.get(ace['SID'], {})
                   userAccess[ace['SID']][userMailboxCN] = rules

        
        s = doc.create_subsection("Who can accessed to this Mailbox")
        table = s.create_table("")

        for k,v in userAccess.items():
            table.add([k,  ' '.join(map(lambda b: '{%s %s}' % (b[0],b[1]), v.items()))])
        table.finished()
        s.finished()

