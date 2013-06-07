# This file is part of the BTA toolset
# (c) EADS CERT and EADS Innovation Works

from bta.miner import Miner
import datetime

@Miner.register
class ListObject(Miner):
    _name_ = "ListObject"
    _desc_ = "ListObject, list Object by categorie and creation or modification date"
    
    def getCategory(self, match):
        ret = self.category.find_one({"name": match})
        if ret:
            return ret['id']
        else:
            return -1
    
    def parseDate(self, dateToTest):
        try:
            date = dateToTest.split('-')
            year = int(date[0])
            month = int(date[1])
            day = int(date[2])
        except Exception as e:
            raise Exception('Invalid date format "%s" expect YYYY-MM-DD ' % options.change)
        return year, month, day
    
    def create(self, year, month, day, category):
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)
        end = datetime.datetime(year, month, day, 23, 59, 59)
        req = {'$and': [
                {"objectCategory" : category},
                {"whenCreated": {"$gt": start, "$lt": end}}],
              }
        for entry in self.datatable.find(req):
            if 'objectSid' in entry:
                result.append([entry['cn'], entry['objectSid'], entry['objectGUID']])
            else:
                result.append([entry['cn'], 'NULL', entry['objectGUID']])
        result.sort(key=lambda x: x[0].lower())
        return result
        
    def change(self, year, month, day, category):
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)
        end = datetime.datetime(year, month, day, 23, 59, 59)
        req = {'$and': [
                {"objectCategory" : category},
                {"whenChanged": {"$gt": start, "$lt": end}}],
              }
        for entry in self.datatable.find(req):
            if 'objectSid' in entry:
                result.append([entry['cn'], entry['objectSid'], entry['objectGUID']])
            else:
                result.append([entry['cn'], 'NULL', entry['objectGUID']])
        result.sort(key=lambda x: x[0].lower())
        return result
        
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--catego", help="Look only for object which categorie match REGEX", metavar="REGEX", required=True)
        parser.add_argument('--change', help='Find all changed object at a given date', metavar='YYYY-MM-DD')
        parser.add_argument('--create', help='Find all creation object at a given date', metavar='YYYY-MM-DD')
    
    def run(self, options, doc):
        category = self.getCategory(options.catego)
        if category < 0:
            doc.add("No categories match [%s]" % options.catego)
            return

        if options.create:
            year, month, day = self.parseDate(options.create)
            create = self.create(year, month, day, category)
            table = doc.create_table("Object[%s] create at %i-%i-%i" % (options.catego, year, month, day))
            table.add(["cn", "SID", "GUID"])
            table.add()
            for attr in create:
                table.add(attr)
            table.finished()
        if options.change:
            year, month, day = self.parseDate(options.change)
            change = self.change(year, month, day, category)
            table = doc.create_table("Object[%s] create at %i-%i-%i" % (options.catego, year, month, day))
            table.add(["cn", "SID", "GUID"])
            table.add()
            for attr in change:
                table.add(attr)
            table.finished()

    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "objectCategory")
        self.assert_field_exists(self.datatable, "cn")
        self.assert_field_type(self.datatable, "objectCategory", int)
        self.assert_field_type(self.datatable, "cn", str, unicode)
        self.assert_field_type(self.datatable, "objectSid", str, unicode)
        self.assert_field_type(self.datatable, "whenChanged", datetime.datetime)
        self.assert_field_type(self.datatable, "whenCreated", datetime.datetime)
    
    