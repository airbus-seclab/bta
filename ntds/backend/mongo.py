
import pymongo
from datetime import datetime
from ntds.normalization import TypeFactory,Normalizer
from ntds.backend import Backend

class MongoNormalizer(Normalizer):
    def empty(self, val):
        return not bool(val)

class MongoTextNormalizer(MongoNormalizer):
    pass
    
class MongoIntNormalizer(MongoNormalizer):
    def normal(self, val):
        return int(val)

class MongoTimestampNormalizer(MongoNormalizer):
    def normal(self, val):
        try:
            ts = int(val)-11644473600 # adjust windows timestamp (from 01/01/1601) to unix epoch
            return datetime.fromtimestamp(ts)
        except ValueError:
            return datetime.fromtimestamp(0)


    
    

class MongoTypeFactory(TypeFactory):
    def Text(self):
        return MongoTextNormalizer()
    def Int(self):
        return MongoIntNormalizer()
    def Timestamp(self):
        return MongoTimestampNormalizer()




@Backend.register("mongo")
class Mongo(Backend):
    def __init__(self, options):
        Backend.__init__(self, options)
        self.colname = options.tablename
        ip,port,self.dbname,_ = (options.connection+":::").split(":",3)
        ip = ip if ip else "127.0.0.1"
        port = int(port) if port else 27017
        self.cnxstr = (ip,port)
        self.cnx = pymongo.Connection(*self.cnxstr)
        self.db = self.cnx[self.dbname]
        self.typefactory = MongoTypeFactory()
    def create_table(self):
        self.fields = [(x[0], getattr(self.typefactory,x[2])())  for x in self.columns]
        self.col = self.db.create_collection(self.colname)
    def insert(self, values):
        d = dict([(name,norm.normal(v)) for (name,norm),v in zip(self.fields, values) if not norm.empty(v)])
        id = self.col.insert(d)
    def count(self):
        return self.col.count()
    
