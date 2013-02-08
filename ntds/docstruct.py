


class DocPart(object):
    _type_ = ""
    def __init__(self, parent, name):
        self.parent = parent
        self.name = name
        self.content = []
    def add_content(self, content=None):
        self.content.append(content)
    def flush(self):
        pass
    def to_json(self):
        content = [ (c.to_json() if hasattr(c,"to_json") else c) for c in self.content ]
        return { "name":self.name, "type": self._type_, "content": content }
    def to_text_file(self, f, level=0):
        f.write("%s\n" % self.name)
        if level <= 1:
            f.write("%s\n" % ({0:"=",1:"-"}.get(level," ")*len(self.name)))
        f.write("\n")
        for c in self.content:
            if hasattr(c, "to_text_file"):
                f.write("\n")
                c.to_text_file(f, level+1)
            else:
                f.write("%s\n" % c)


class Table(DocPart):
    _type_ = "table"
    def format_table(self, width_hint=160):
        sep = " | "
        cross = "-+-"
        tl = map(max, zip(*[map(len,l) for l in self.content if l]))
        total_width = sum(tl)+len(tl)*len(sep)
        if total_width > width_hint:
            tl = [max(2,int(round(float(l*width_hint)/total_width))) for l in tl]
        fmt = sep.join(["%%-%is"]*len(tl)) % tuple(tl)
        hfmt = cross.join(["%%-%is"]*len(tl)) % tuple(tl)
        hline = hfmt % tuple(["-"*l for l in tl])
        return fmt, hline
        

    def to_text_file(self, f, level=0):
        f.write("%s\n" % self.name)
        fmt,hline = self.format_table()
        fmt += "\n"
        hline += "\n"
        for l in self.content:
            if l:
                f.write(fmt % tuple(l))
            else:
                f.write(hline)
        f.write("\n")

class DocStruct(DocPart):
    _type_ = "struct"
    def create_subelement(self, elt):
        self.content.append(elt)
        return elt    

    def create_subsection(self, name):
        return self.create_subelement(self.__class__(parent=self, name=name))

    def create_table(self, name):
        return self.create_subelement(Table(self, name))


if __name__ == "__main__":
    import sys
    d = DocStruct(None, "root")
    d.add_content("foo")
    d.add_content("bar")
    s1 = d.create_subsection("sub1")
    s1.add_content("foobar")
    s1.add_content("foobarbar")
    t = s1.create_table("table 1")
    t.add_content(["n1","c2","test3"])
    t.add_content("")
    t.add_content(["1","2","3"])
    t.add_content(["7","5","6"])
    t.add_content(["6","45648","2"])
    t.add_content("")
    t.add_content(["aze","az","aa"])
    s2 = d.create_subsection("sub2")
    s2.add_content("foobar")
    s2.add_content("foobar")
    s2.add_content("foobartrain!")
    s3 = s2.create_subsection("subsub3")
    s3.add_content("barfoo")

    d.to_text_file(sys.stdout)
