# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

import os, sys

load_rid_path=os.path.join(os.environ['HOME'], 'local_rid.py')
local_relative_domains_sid=None

class Family(object):
    @classmethod
    def find_siblings(cls, node, datatable):
        siblings=list()
        id_siblings=[s["DNT_col"] for s in datatable.find({"PDNT_col":node['DNT_col']},{"DNT_col":1})]
        for i in id_siblings:
            siblings.append(datatable.find({"DNT_col":i}).limit(1)[0])
        return siblings

    @classmethod
    def find_parents(cls, node, datatable):
        parents=list()
        for a in node['Ancestors_col']:
            parents.append(datatable.find({"DNT_col":a}).limit(1)[0])
        return parents



class Sid(object):
    def __init__(self, sid, dt):
        try:
            self.obj = dt.find_one({"objectSid": sid})
        except:
            self.obj = {'cn': '(null)', 'objectSid': '(null)'}

    def __str__(self):
        if not self.obj:
            return '(null obj)'
        try:
            s =u'{0[name]}'.format(self.obj)
        except:
            s = self.obj['sid']
        return s

    def getUserAccountControl(self): #to replace
        if 'userAccountControl' in self.obj:
            l = [ f for  f,v in self.obj['userAccountControl']['flags'].items() if v ]
            return ', '.join(l)
        else:
            return ''

    @staticmethod
    def resolveRID(sid): # to replace
        pos = sid.rfind('-')
        domainpart = sid[:pos]
        userpart = sid[pos:]
        if domainpart in local_relative_domains_sid:
            return local_relative_domains_sid[domainpart] + userpart
        else:
            return sid


class Record(object):
    def __init__(self, **dbrecord):
        self.obj = dbrecord

    def __getattr__(self, attr):
        return self.obj.get(attr, None)

    def __getitem__(self, attr):
        return self.obj.get(attr, None)

    def __contains__(self, attr):
        return self.obj.__contains__(attr)

    def __repr__(self):
        return self.obj.__str__()

    def __str__(self):
        return self.obj.__str__()

