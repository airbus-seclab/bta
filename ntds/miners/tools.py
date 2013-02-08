import os, sys

load_rid_path=os.path.join(os.environ['HOME'], 'local_rid.py')

local_relative_domains_sid=None
try:
    execfile(load_rid_path)
    if not local_relative_domains_sid:
        sys.stderr.write("%s: No local_relative_domains_sid dictionnary?\n" % load_rid_path)
except:
    sys.stderr.write("Cannot read local RID files (%s), I will not resolve RID!\n" % load_rid_path)

class Sid(object):
    @staticmethod
    def resolveRID(sid):
        pos = sid.rfind('-')
        domainpart = sid[:pos]
        userpart = sid[pos:]
        if domainpart in local_relative_domains_sid:
            return local_relative_domains_sid[domainpart] + userpart
        else:
            return sid

class Group(object):
    def __init__(self, datatable, **kwargs):
        kwargs['objectCategory'] = '5945'
        self.obj = datatable.find_one(kwargs)
        if not self.obj:
            raise Exception("No such group: %r" % kwargs)

    def __str__(self):
        return '{0[objectSid]:50} {0[cn]}'.format(self.obj).encode('utf-8')

    def __getattr__(self, attr):
        if attr in self.obj:
            return self.obj[attr]
        return super(Group, self).__getattr__(self, attr)

    def __getitem__(self, attr):
        if attr in self.obj:
            return self.obj[attr]
        return super(Group, self).__getitem__(self, attr)

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
