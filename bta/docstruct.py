# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import StringIO

class DocPart(object):
    _type_ = "struct"
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name
        self.content = []
        self.done = False
    def add(self, content=None):
        self.content.append(content)
        self.flush()

    def create_subelement(self, elt):
        self.content.append(elt)
        return elt

    def create_subsection(self, name):
        return self.create_subelement(DocPart(parent=self, name=name))

    def create_table(self, name):
        return self.create_subelement(Table(self, name))

    def create_list(self, name):
        return self.create_subelement(List(self, name))
    
    def create_raw(self, name):
        return self.create_subelement(Raw(self, name))

    def flush(self):
        self.parent.flush()

    def to_json(self):
        content = [ (c.to_json() if hasattr(c,"to_json") else c) for c in self.content ]
        return { "name":self.name, "type": self._type_, "content": content }

    def finished(self):
        self.done = True
        self.flush()

    def format_content(self, c):
        return "%s\n" % c

    def live_output(self, stream, level=0):
        stream.write("%s\n" % self.name)
        if level <= 1:
            stream.write("%s\n" % ({0:"=",1:"-"}.get(level," ")*len(self.name)))
        stream.write("\n")

        i = 0
        finishing = False
        while True:
            while i < len(self.content):
                c = self.content[i]
                i += 1

                if hasattr(c, "live_output"):
                    stream.write("\n")
                    o = c.live_output(stream, level+1)
                    try:
                        while True:
                            o.next()
                            if finishing:
                                o.send(True)
                            d = yield
                            if d:
                                self.done = True
                                finishing = True
                                o.send(True)
                    except StopIteration:
                        pass

                else:
                    stream.write(self.format_content(c))
            if self.done:
                if i >= len(self.content):
                    break
            else:
                d = yield
                if d:
                    self.done = True
                    finishing = True

        stream.write("\n")

    def format_doc(self, formatter, lvl=0):
        formatter.add_section(self.name, lvl)
        for c in self.content:
            if isinstance(c, DocPart):
                c.format_doc(formatter, lvl+1)
            else:
                formatter.add_content(c)


class RootDoc(DocPart):
    def __init__(self, name):
        DocPart.__init__(self, None, name)
    def flush(self):
        pass
    def start_stream(self, stream=None):
        pass
    def finish_stream(self):
        pass

class LiveRootDoc(RootDoc):
    def flush(self):
        self.live.next()
    def start_stream(self, stream=None):
        if stream is None:
            import sys
            stream = sys.stdout
        self.live = self.live_output(stream)
    def finish_stream(self):
        try:
            self.live.next() # just in case the generator was not started yet
            self.live.send(True)
        except StopIteration:
            pass
        else:
            raise Exception("live stream iteration did not stop")


class Table(DocPart):
    _type_ = "table"
    _last_col_nb = 0

    def format_content(self, c):
        if c:
            self._last_col_nb = len(c)
            fmt = " | ".join(["%-20s"]*len(c)) + "\n"
            return fmt % tuple(c)
        else:
            return "-+-".join(["-"*20]*self._last_col_nb) + "\n"

    def format_doc(self, formatter, lvl=0):
        formatter.add_table(self.name, [map(unicode, x) if x else None for x in self.content])


class List(DocPart):
    _type_ = "list"
    list_level = 0

    def format_content(self, c):
        return "%s%s %s\n" % (" "*self.list_level,
                              ["*","+","-"][self.list_level%3],
                              c)

    def create_list(self, name):
        sublist = self.create_subelement(List(self, name))
        sublist.list_level = self.list_level+1
        return sublist

    def format_doc(self, formatter, lvl=0, sublist=None):

        if sublist is None:
            sublist=self
        # Print all unicode in my content
        import bta.docstruct
        all_unicodes= [a for a in sublist.content if type(a) is unicode or type(a) is str]

        formatter.add_list(sublist.name, lvl , all_unicodes)
        # Launch the function on all remaining lists in the content
        c = [ v for v in sublist.content if type(v) is bta.docstruct.List]
        for t in c:
            self.format_doc(formatter, lvl+1, sublist=t)


class Raw(DocPart):
    _type_ = "raw"
    def __init__(self, parent, name):
        DocPart.__init__(self, parent, name)
        self.raw_content = StringIO.StringIO()
    def add(self, content):
        if type(content) is unicode:
            content = content.encode("utf8")
        self.raw_content.write(content)
    def format_doc(self, formatter, lvl=None):
        formatter.add_raw(self.name, self.raw_content.getvalue())
    def finished(self):
        self.content = [self.raw_content.getvalue()]
        DocPart.finished(self)
    def to_json(self):
        content = [ self.raw_content.getvalue() ]
        return { "name":self.name, "type": self._type_, "content": content }



def w():
    import time
    time.sleep(0.1)

if __name__ == "__main__":
    #pylint: disable=multiple-statements
    d = LiveRootDoc("root")
    d.start_stream()
    d.add("foo") ;w()
    d.add("bar") ;w()
    s1 = d.create_subsection("sub1")
    s1.add("foobar") ;w()
    s1.add("foobarbar") ;w()
    t = s1.create_table("table 1") ;w()
    t.add(["n1","c2","test3"]) ;w()
    t.add("") ;w()
    t.add(["1","2","3"])
    t.add(["7","5","6"]) ;w()
    s2 = d.create_subsection("sub2") ;w()
    s2.add("foobar") ;w()
    s2.add("foobar") ;w()
    s2.add("foobartrain!") ;w()
    t.add(["6","45648","2"]) ;w()
    t.add("") ;w()
    t.add(["aze","az","aa"]) ;w()
    t.finished()
    s1.finished()
    l = s2.create_list("list of things")
    l.add("thing 1")
    l.add("thing 2")
    l.add("thing 3")
    s3 = s2.create_subsection("subsub3") ;w()
    s3.add("barfoo") ;w()
    s3.add("barfoo") ;w()
    s3.add("barfoo") ;w()
    s3.add("barfoo") ;w()
    s2.add("unpushed content of sub2..1"); w()
    s2.add("unpushed content of sub2..2"); w()
    s2.add("unpushed content of sub2..3"); w()

    d.finish_stream()

#    d.to_text_file(sys.stdout)
