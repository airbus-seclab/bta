# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

import os, sys

FLAG_DISABLED = 0x2
FLAG_PASSWD_NEVER_EXPIRE = 0x10000
FLAG_EXPIRED  = 0x800000

load_rid_path=os.path.join(os.environ['HOME'], 'local_rid.py')
local_relative_domains_sid=None

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
            uac = int(self.obj['userAccountControl'])
            flags=[]
            if uac & FLAG_PASSWD_NEVER_EXPIRE:
                flags.append('PASSWD_NEVER_EXPIRE')
            if uac & FLAG_DISABLED:
                flags.append('DISABLED')
            if uac & FLAG_EXPIRED:
                flags.append('EXPIRED')
            if flags:
                return ', '.join(flags)
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

