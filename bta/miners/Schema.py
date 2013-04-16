from bta.miners import Miner, ListACE
import sys, datetime

@Miner.register
class Schema(Miner):
    _name_ = "Schema"
    _desc_ = "Schema integrity: owner of category, big change in schema and so on"
    
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--timelineAS', choices=['recorded', 'created', 'changed'], help='Timeline of change in attribute schema')
        parser.add_argument('--timelineCS', choices=['recorded', 'created', 'changed'], help='Timeline of change in class schema')
        parser.add_argument('--changeAS', help='Find change related to attribute schema', metavar='YYYY-MM-DD')
        parser.add_argument('--createAS', help='Find creation related to attribute schema', metavar='YYYY-MM-DD')
        parser.add_argument('--changeCS', help='Find change related to class schema', metavar='YYYY-MM-DD')
        parser.add_argument('--createCS', help='Find creation related to class schema', metavar='YYYY-MM-DD')
        parser.add_argument('--owner', help='Owner of schema and category object', action="store_true")
    
    def timeline(self, option, atrib):
        timecreated = {}
        timechanged = {}
        timerecord = {}
        for r in self.datatable.find({"objectCategory": str(atrib)}):
            rectime = str(r["RecordTime"])[:-6]
            changetime = str(r["whenChanged"])[:-6]
            createtime = str(r["whenCreated"])[:-6]
            recid = r["RecId"]
            
            if rectime in timerecord: timerecord[rectime].append(recid)
            else: timerecord[rectime] = [recid]
            if createtime in timecreated: timecreated[createtime].append(recid)
            else: timecreated[createtime] = [recid]
            if changetime in timechanged: timechanged[changetime].append(recid)
            else: timechanged[changetime] = [recid]
        
        if option == 'recorded':
            timerecord = sorted(timerecord.items(), key=lambda x: x[0])
            return timerecord
        elif option == 'created':
            timecreated = sorted(timecreated.items(), key=lambda x: x[0])
            return timecreated
        elif option == 'changed':
            timechanged = sorted(timechanged.items(), key=lambda x: x[0])
            return timechanged
    
    def owner(self):
        SchemaSecuDescriptor = {}
        root = self.datatable.find_one({"cn": "Schema"})
        SchemaSecuDescriptor[root["nTSecurityDescriptor"]] = [root["RecId"]]
        for r in self.datatable.find({"objectCategory": str(self.categories.attribute_schema)}):
            idSecu = r["nTSecurityDescriptor"]
            if idSecu in SchemaSecuDescriptor: SchemaSecuDescriptor[idSecu].append(r["RecId"])
            else: SchemaSecuDescriptor[idSecu] = [r["RecId"]]
        for r in self.datatable.find({"objectCategory": str(self.categories.class_schema)}):
            idSecu = r["nTSecurityDescriptor"]
            if idSecu in SchemaSecuDescriptor: SchemaSecuDescriptor[idSecu].append(r["RecId"])
            else: SchemaSecuDescriptor[idSecu] = [r["RecId"]]
        SchemaSecuDescriptor = sorted(SchemaSecuDescriptor.items(), key=lambda x: x[0])
        return SchemaSecuDescriptor
    
    def change(self, year, month, day, atrib):
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)
        end = datetime.datetime(year, month, day, 23, 59, 59)
        req = {'$and': [
                {"objectCategory" : {"$in": 
                    [str(self.categories.class_schema), str(atrib)]}},
                {"whenChanged": {"$gt": start, "$lt": end}}],
              }
        for entry in self.datatable.find(req):
            result.append([entry['cn'], entry['objectGUID']])
        result.sort(key=lambda x: x[0].lower())
        return result
        
    def create(self, year, month, day, atrib):
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)
        end = datetime.datetime(year, month, day, 23, 59, 59)
        req = {'$and': [
                {"objectCategory" : {"$in": 
                    [str(self.categories.class_schema), str(atrib)]}},
                {"whenCreated": {"$gt": start, "$lt": end}}],
              }
        for entry in self.datatable.find(req):
            result.append([entry['cn'], entry['objectGUID']])
        result.sort(key=lambda x: x[0].lower())
        return result
    
    def parseDate(self, dateToTest):
        try:
            date = dateToTest.split('-')
            year = int(date[0])
            month = int(date[1])
            day = int(date[2])
        except Exception as e:
            raise Exception('Invalid date format "%s" expect YYYY-MM-DD ' % options.change)
        return year, month, day
    
    def run(self, options, doc):
        if options.timelineAS:
            table = doc.create_table("Timeline of %s attribute schema" % (options.timelineAS))
            table.add(["Date", "Affected attribute schema"])
            table.add()
            lisTimeline = self.timeline(options.timelineAS, self.categories.attribute_schema)
            for x in lisTimeline:
                table.add([x[0], len(x[1])])
            table.finished()
        if options.timelineCS:
            table = doc.create_table("Timeline of %s class schema" % (options.timelineCS))
            table.add(["Date", "Affected class schema"])
            table.add()
            lisTimeline = self.timeline(options.timelineCS, self.categories.class_schema)
            for x in lisTimeline:
                table.add([x[0], len(x[1])])
            table.finished()
        if options.owner:
            table = doc.create_table("Owner of schema")
            table.add(["Name", "SID", "Number of schema owned"])
            table.add()
            SchemaSecuDescriptor = self.owner()
            hdlACE = ListACE.ListACE()
            for shema in SchemaSecuDescriptor:
                numOwnShema = len(shema[1])
                desc = hdlACE.getSecurityDescriptor(shema[0])
                ownersid = desc['value']['Owner']
                name = self.datatable.find_one({'objectSid': ownersid})['cn']
                table.add([name, ownersid, numOwnShema])
            table.finished()
        if options.changeAS:
            year, month, day = self.parseDate(options.changeAS)
            change = self.change(year, month, day, self.categories.attribute_schema)
            table = doc.create_table("Schema change at %i-%i-%i" % (year, month, day))
            table.add(["cn", "GUID"])
            table.add()
            for attr in change:
                table.add(attr)
            table.finished()
        if options.createAS:
            year, month, day = self.parseDate(options.createAS)
            create = self.create(year, month, day, self.categories.attribute_schema)
            table = doc.create_table("Schema created at %i-%i-%i" % (year, month, day))
            table.add(["cn", "GUID"])
            table.add()
            for attr in create:
                table.add(attr)
            table.finished()
        if options.changeCS:
            year, month, day = self.parseDate(options.changeCS)
            change = self.change(year, month, day, self.categories.class_schema)
            table = doc.create_table("Schema change at %i-%i-%i" % (year, month, day))
            table.add(["cn", "GUID"])
            table.add()
            for attr in change:
                table.add(attr)
            table.finished()
        if options.createCS:
            year, month, day = self.parseDate(options.createCS)
            create = self.create(year, month, day, self.categories.class_schema)
            table = doc.create_table("Schema created at %i-%i-%i" % (year, month, day))
            table.add(["cn", "GUID"])
            table.add()
            for attr in create:
                table.add(attr)
            table.finished()
    
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "objectCategory")
        self.assert_field_type(self.datatable, "objectCategory", str, unicode)
        self.assert_field_type(self.datatable, "RecordTime", datetime.datetime)
        self.assert_field_type(self.datatable, "whenChanged", datetime.datetime)
        self.assert_field_type(self.datatable, "whenCreated", datetime.datetime)
        self.assert_field_type(self.datatable, "RecId", int)
        self.assert_field_type(self.datatable, "cn", str, unicode)
        self.assert_field_type(self.datatable, "objectSid", str, unicode)
        self.assert_field_type(self.datatable, "nTSecurityDescriptor", int)
        