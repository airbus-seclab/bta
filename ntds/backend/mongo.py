
import pymongo
import struct
from datetime import datetime
from ntds.normalization import TypeFactory,Normalizer
from ntds.backend import Backend, BackendTable
import ntds.sd
import ntds.tools

class MongoNormalizer(Normalizer):
    def empty(self, val):
        return not bool(val)

class MongoTextNormalizer(MongoNormalizer):
    pass
    
class MongoIntNormalizer(MongoNormalizer):
    def normal(self, val):
        v = int(val)
        if -0x8000000000000000 <= v < 0x8000000000000000:
            return v
        return val

class MongoTimestampNormalizer(MongoNormalizer):
    def normal(self, val):
        try:
            ts = int(val)-11644473600 # adjust windows timestamp (from 01/01/1601) to unix epoch
            return datetime.fromtimestamp(ts)
        except ValueError:
            return datetime.fromtimestamp(0)

class MongoNTSecDesc(MongoNormalizer):
    def normal(self, val):
        return struct.unpack("Q", val.decode("hex"))[0]

class MongoSID(MongoNormalizer):
    def normal(self, val):
        try:
            val = val.strip().decode("hex")
        except:
            return val
        if val:
            return ntds.tools.decode_sid(val,">")
        return None
    
class MongoGUID(MongoNormalizer):
    def normal(self, val):
        val = val.strip().decode("hex")
        if val:
            return ntds.tools.decode_guid(val)
        return None
    
class MongoSecurityDescriptor(MongoNormalizer):
    def normal(self, val):
        val = val.strip().decode("hex")
        if val:
            return ntds.sd.sd_to_json(val)
        return None
    

class MongoTypeFactory(TypeFactory):
    def Text(self):
        return MongoTextNormalizer()
    def Int(self):
        return MongoIntNormalizer()
    def Timestamp(self):
        return MongoTimestampNormalizer()
    def NTSecDesc(self):
        return MongoNTSecDesc()
    def SID(self):
        return MongoSID()
    def GUID(self):
        return MongoGUID()
    def SecurityDescriptor(self):
        return MongoSecurityDescriptor()

class MongoTable(BackendTable):
    def __init__(self, options, db, name):
        BackendTable.__init__(self, options, db, name)
        self.typefactory = MongoTypeFactory()
        self.col = db[name]
        self.fields = None

    def create(self, columns):
        self.fields = [(c.name, getattr(self.typefactory, c.type)())  for c in columns]
        self.col = self.db.create_collection(self.name)
        for c in columns:
            if c.index:
                self.col.create_index(c.name)
        
    def insert(self, values):
        return self.col.insert(values)

    def insert_fields(self, values):
        d = dict([(name,norm.normal(v)) for (name,norm),v in zip(self.fields, values) if not norm.empty(v)])
        return self.insert(d)

    def count(self):
        return self.col.count()

    def find(self, *args, **kargs):
        return self.col.find(*args, **kargs)
    def find_one(self, *args, **kargs):
        return self.col.find_one(*args, **kargs)


@Backend.register("mongo")
class Mongo(Backend):
    def __init__(self, options):
        Backend.__init__(self, options)
        ip,port,self.dbname,_ = (options.connection+":::").split(":",3)
        ip = ip if ip else "127.0.0.1"
        port = int(port) if port else 27017
        self.cnxstr = (ip,port)
        self.cnx = pymongo.Connection(*self.cnxstr)
        self.db = self.cnx[self.dbname]


    def open_table(self, name):
        return MongoTable(self.options, self.db, name)

    
