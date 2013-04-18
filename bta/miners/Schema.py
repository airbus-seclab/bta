from bta.miners import Miner, ListACE
import sys, datetime

@Miner.register
class Schema(Miner):
    _name_ = "Schema"
    _desc_ = "Schema integrity: owner of category, big change in schema and so on"
    
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--timeline', choices=['recorded', 'created', 'changed'], help='Timeline of the big change in schema')
        parser.add_argument('--change', help='Find change not related to the schema', metavar='YYYY-MM-DD')
        parser.add_argument('--owner', help='Owner of schema and category object', action="store_true")
    
    def timeline(self, option):
        timecreated = {}
        timechanged = {}
        timerecord = {}
        for r in self.datatable.find({"objectCategory": str(self.categories.attribute_schema)}):
            rectime = str(r["RecordTime"])[:-6]
            changetime = str(r["whenChanged"])[:-6]
            createtime = str(r["whenCreated"])[:-6]
            recid = r["DNT_col"]
            
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
        SchemaSecuDescriptor[root["nTSecurityDescriptor"]] = [root["DNT_col"]]
        for r in self.datatable.find({"objectCategory": str(self.categories.attribute_schema)}):
            idSecu = r["nTSecurityDescriptor"]
            if idSecu in SchemaSecuDescriptor: SchemaSecuDescriptor[idSecu].append(r["DNT_col"])
            else: SchemaSecuDescriptor[idSecu] = [r["DNT_col"]]
        SchemaSecuDescriptor = sorted(SchemaSecuDescriptor.items(), key=lambda x: x[0])
        return SchemaSecuDescriptor
    
    def change(self, year, month, day):
        result = list()
        start = datetime.datetime(year, month, day, 0, 0, 0)
        end = datetime.datetime(year, month, day, 23, 59, 59)
        req = {'$and': [
                {"objectCategory" : {"$in": 
                    [str(self.categories.person), str(self.categories.group), str(self.categories.computer)]}},
                {"whenChanged": {"$gt": start, "$lt": end}}],
              }
        for entry in self.datatable.find(req):
            result.append([entry['cn'], entry['objectSid']])
        result.sort(key=lambda x: x[0].lower())
        return result
        
    def run(self, options, doc):
        if options.timeline:
            table = doc.create_table("Timeline of %s schema" % (options.timeline))
            table.add(["Date", "Number of affected schema"])
            table.add()
            lisTimeline = self.timeline(options.timeline)
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
        if options.change:
            try:
                date = options.change.split('-')
                year = int(date[0])
                month = int(date[1])
                day = int(date[2])
            except Exception as e:
                raise Exception('Invalid date format "%s" expect YYYY-MM-DD ' % options.change)
            change = self.change(year, month, day)
            table = doc.create_table("Users/groups/computers change at %i-%i-%i" % (year, month, day))
            table.add(["Name", "SID"])
            table.add()
            for user in change:
                table.add(user)
            table.finished()
    
    def assert_consistency(self):
        Miner.assert_consistency(self)
        self.assert_field_exists(self.datatable, "objectCategory")
        self.assert_field_type(self.datatable, "objectCategory", str, unicode)
        self.assert_field_type(self.datatable, "RecordTime", datetime.datetime)
        self.assert_field_type(self.datatable, "whenChanged", datetime.datetime)
        self.assert_field_type(self.datatable, "whenCreated", datetime.datetime)
        self.assert_field_type(self.datatable, "DNT_col", int)
        self.assert_field_type(self.datatable, "cn", str, unicode)
        self.assert_field_type(self.datatable, "objectSid", str, unicode)
        self.assert_field_type(self.datatable, "nTSecurityDescriptor", int)
        
