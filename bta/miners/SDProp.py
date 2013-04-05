from bta.miners import Miner, ListACE
from pprint import pprint
import re

@Miner.register
class SDProp(Miner):
    _name_ = "SDProp"
    _desc_ = "check integrity of SDHolder and protected account"
    
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--list", action="store_true", help="Find accounts protected by SDHolder")
        parser.add_argument("--orphan", action="store_true", help="Find accounts unlinked from SDHolder")
        parser.add_argument("--checkACE", action="store_true", help="Check ACE replicated by AdminSDHolder")
    
    def list(self):
        user = list()
        group = list()
        t = list()
        for r in self.dt.find({"adminCount":{"$exists": True, "$ne":"0"}}):
            if int(r["objectCategory"]) == self.categories.person:
                user.append([r["cn"], 'User', r["objectSid"]])
            elif int(r["objectCategory"]) == self.categories.group:
                group.append([r["cn"], 'Group', r["objectSid"]])
            else:
                print '***** Unknown category (%d) for %s' % (r["objectCategory"], r["objectSid"])
        user.sort()
        group.sort()
        for g in group:
            t.append(g)
        for u in user:
            t.append(u)
        t.insert(0, [])
        t.insert(0, ["cn","type","SID"])
        return t
        
    def orphanSD(self):
        user = list()
        group = list()
        t = list()
        for r in self.dt.find({"adminCount":{"$exists": True, "$ne":"1"}}):
            if int(r["objectCategory"]) == self.categories.person:
                user.append([r["cn"], 'User', r["objectSid"]])
            elif int(r["objectCategory"]) == self.categories.person:
                group.append([r["cn"], 'Group', r["objectSid"]])
            else:
                print '***** Unknown category (%d) for %s' % (r["objectCategory"], r["objectSid"])
        user.sort()
        group.sort()
        for g in group:
            t.append(g)
        for u in user:
            t.append(u)
        t.insert(0, [])
        t.insert(0, ["cn","type","SID"])
        return t
        
    def checkACE(self):
        secDesc = int(self.dt.find_one({"cn": "AdminSDHolder"})['nTSecurityDescriptor'])
        hdlACE = ListACE.ListACE()
        securitydescriptor = hdlACE.getSecurityDescriptor(secDesc)
        aceList = hdlACE.extractACE(securitydescriptor)
        
        t = list()
        t.append(["Entry name","Acces","Target"])
        t.append([])
        for ace in aceList:
            name = self.dt.find_one({"objectSid": ace['SID']}, {"cn"})['cn']
            if ace['InheritedObjectType'] != None:
                cible = self.dt.find_one({"schemaIDGUID" : re.compile(ace['InheritedObjectType'], re.IGNORECASE)})
                if cible == None: 
                    cible = self.dt.find_one({"rightsGuid" : re.compile(ace['InheritedObjectType'], re.IGNORECASE)})
                cible = cible['cn']
            elif ace['ObjectType'] != None:
                cible = self.dt.find_one({"schemaIDGUID" : re.compile(ace['ObjectType'], re.IGNORECASE)})
                if cible == None: 
                    cible = self.dt.find_one({"rightsGuid" : re.compile(ace['ObjectType'], re.IGNORECASE)})
                cible = cible['cn']
            else:
                cible = 'ALL'
            t.append([name, ace['Type'], cible])
        return t

    def run(self, options, doc):        
        if options.list:
            toDisplay = self.list()
            t = doc.create_table("Acount protected by SDHolder")
            for disp in toDisplay:
                t.add(disp)
            t.flush()
            t.finished()
        elif options.orphan:
            toDisplay = self.orphanSD()
            t = doc.create_table("Accounts unlinked from SDHolder")
            for disp in toDisplay:
                t.add(disp)
            t.flush()
            t.finished()
        elif options.checkACE:
            toDisplay = self.checkACE()
            t = doc.create_table("Rigts replicated by SDHolder on protected account")
            for disp in toDisplay:
                t.add(disp)
            t.flush()
            t.finished()
