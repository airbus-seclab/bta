# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

from bta.miner import Miner
import datetime

@Miner.register
class ListObject(Miner):
    _name_ = "ListObject"
    _desc_ = "ListObject, list Object by categorie and creation or modification date"
    _uses_ = [ "raw.datatable", "raw.category" ]


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
        except Exception:
            raise ValueError('Invalid date format for "%s". Expecting YYYY-MM-DD ' % dateToTest)
        return year, month, day

    def select(self, year, month, day, category, year2=None, month2=None, day2=None, condition="whenCreated"):
        year2 = year if year2 is None else year2
        month2 = month if month2 is None else month2
        day2 = day if day2 is None else day2
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)
        end = datetime.datetime(year2, month2, day2, 23, 59, 59)
        req = {'$and': [
                {"objectCategory" : category},
                {condition: {"$gt": start, "$lt": end}}],
              }
        for entry in self.datatable.find(req):
            if 'objectSid' in entry:
                result.append([entry['cn'], entry['objectSid'], entry['objectGUID'], entry[condition]])
            else:
                result.append([entry['cn'], 'NULL', entry['objectGUID'], entry[condition]])
        result.sort(key=lambda x: x[0].lower())
        return result


    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument("--catego", help="Look only for object which categorie match REGEX", metavar="REGEX", required=True)
        parser.add_argument('--change', action="store_true", help='Find all changed object at a given date')
        parser.add_argument('--create', action="store_true", help='Find all creation object at a given date')
        parser.add_argument('--start-date', required=True, help='Start date', metavar='YYYY-MM-DD')
        parser.add_argument('--end-date', help='End date (if empty then only 1 day is taken)', metavar='YYYY-MM-DD')

    def run(self, options, doc):
        category = self.getCategory(options.catego)
        if category < 0:
            doc.add("No categories match [%s]" % options.catego)
            return

        end_date = options.end_date if not options.end_date is None else options.start_date

        if options.create:
            cond,verb = ("whenCreated","created")
        else:
            cond,verb = ("whenChanged","changed")

        year, month, day = self.parseDate(options.start_date)
        year2, month2, day2 = self.parseDate(end_date)
        create = self.select(year, month, day, category, year2, month2, day2, condition=cond)
        table = doc.create_table("Object[%s] %s between %i-%i-%i and %i-%i-%i" % (options.catego, verb, year, month, day, year2, month2, day2))
        table.add(["cn", "SID", "GUID","Date"])
        table.add()
        for attr in create:
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
