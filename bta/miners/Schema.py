from bta.miners import Miner, ListACE


@Miner.register
class Schema(Miner):
    _name_ = "Schema"
    _desc_ = "Schema integrity: owner of category, big change in schema and so on"
    
    @classmethod
    def create_arg_subparser(cls, parser):
        parser.add_argument('--timeline', choices=['recorded', 'created', 'changed'], help='Timeline of the big change in schema')
        parser.add_argument('--owner', help='Owner of schema and category object', action="store_true")
    
    def timeline(self, option):
        idShema = self.dt.find_one({"cn": "Class-Schema"})['RecId']
        timecreated = {}
        timechanged = {}
        timerecord = {}
        for r in self.dt.find({"objectCategory": str(idShema)}):
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
        root = self.dt.find_one({"cn": "Schema"})
        SchemaSecuDescriptor[root["nTSecurityDescriptor"]] = [root["RecId"]]
        idShema = self.dt.find_one({"cn": "Class-Schema"})['RecId']
        for r in self.dt.find({"objectCategory": str(idShema)}):
            idSecu = r["nTSecurityDescriptor"]
            if idSecu in SchemaSecuDescriptor: SchemaSecuDescriptor[idSecu].append(r["RecId"])
            else: SchemaSecuDescriptor[idSecu] = [r["RecId"]]
        SchemaSecuDescriptor = sorted(SchemaSecuDescriptor.items(), key=lambda x: x[0])
        return SchemaSecuDescriptor
    
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
                name = self.dt.find_one({'objectSid': ownersid})['cn']
                table.add([name, ownersid, numOwnShema])
            
            

