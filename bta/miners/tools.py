import os, sys

FLAG_DISABLED = 0x2
FLAG_PASSWD_NEVER_EXPIRE = 0x10000
FLAG_EXPIRED  = 0x800000

load_rid_path=os.path.join(os.environ['HOME'], 'local_rid.py')
local_relative_domains_sid=None

class Sid(object):
    def __init__(self, datatable, verbose=False, **kwargs):
        self.verbose = verbose
        try:
            self.obj = datatable.find_one(kwargs)
        except:
            self.obj = {'cn': '(null)', 'objectSid': '(null)'}

    def __str__(self):
        if not self.obj:
            return '(null obj)'
        try:
            if self.verbose:
                s =u'{0[cn]} ({0[objectSid]})'.format(self.obj)
            else:
                s =u'{0[cn]}'.format(self.obj)
        except:
            s = self.obj['objectSid']
        return s.encode('utf-8')

    def getUserAccountControl(self):
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
    def resolveRID(sid):
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


class Group(object):
    def __init__(self, datatable, **kwargs):
        kwargs['objectCategory'] = '5945'
        self.obj = datatable.find_one(kwargs)
        if not self.obj:
            raise Exception("No such group: %r" % kwargs)

    def __str__(self):
        return '{0[objectSid]:50} {0[cn]}'.format(self.obj).encode('utf-8')

    def __getattr__(self, attr):
        return self.obj.get(attr, None)

    def __getitem__(self, attr):
        return self.obj.get(attr, None)

class User(object):
    def __init__(self, datatable, **kwargs):
        self.obj = datatable.find_one(kwargs)
        if not self.obj:
            raise Exception("No such user: %r" % kwargs)

    def __str__(self):
        return '{0[objectSid]:50} {0[cn]}'.format(self.obj).encode('utf-8')

    def __getattr__(self, attr):
        if attr in self.obj:
            return self.obj[attr]
        return super(User, self).__getattr__(self, attr)

    def __getitem__(self, attr):
        if attr in self.obj:
            return self.obj[attr]
        return super(User, self).__getitem__(self, attr)
