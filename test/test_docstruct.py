# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import pytest
from bta.docstruct import *
import bta.formatters.rest
import bta.formatters.raw
import bta.formatters.rawzip
import StringIO
import zipfile

def fill_doc(d):
    d.add("foo")
    d.add("bar")
    s1 = d.create_subsection("sub1")
    s1.add("foobar")
    s1.add("foobarbar")
    t = s1.create_table("table 1")
    t.add(["n1","c2","test3"])
    t.add("")
    t.add(["1","2","3"])
    t.add(["7","5","6"])
    s2 = d.create_subsection("sub2")
    s2.add("foobar")
    s2.add("foobar")
    r = s2.create_raw("raw part")
    s2.add("foobartrain!")
    t.add(["6","45648","2"])
    t.add("")
    r.add("abc")
    r.add("defg")
    t.add(["aze","az","aa"])
    t.finished()
    r.add("hij\nklmnop")
    s1.finished()
    r.finished()
    l = s2.create_list("list of things")
    l.add("thing 1")
    l.add("thing 2")
    l.add("thing 3")
    s3 = s2.create_subsection("subsub3")
    s3.add("barfoo")
    s3.add("barfoo")
    s3.add("barfoo")
    s3.add("barfoo")
    s2.add("unpushed content of sub2..1")
    s2.add("unpushed content of sub2..2")
    s2.add("unpushed content of sub2..3")


def test_docstruct_livestream():
    stream = StringIO.StringIO()
    d = LiveRootDoc("root")
    d.start_stream(stream)
    fill_doc(d)
    d.finish_stream()

    result = ("eJytkk2OwjAMhffvFJktCKSWv9nMYdyS0jIlqRJXIyEOj5sCC2oQi7Ei2fps5"
              "T0lDt4zfiSAynsU\nFIDYFxkWEokNaEypyVS01mSAy8w0LqbMVcw28uqJJo1J"
              "zFX6AkMzIXKaCcHPDpKLnT670fFWu0KD\nMrvebNffn5n7j7egs9Vc0Fk1R6S"
              "4QPr9XPt9INCf6SgwQEW5t9Whbo74bU/Od/dZDtS4L6BtIhtf\nGa4bd4jAbK"
              "xkb+5V/qhWo6gcqeSO2x5OE3rX9bG2e1N6x9YlhcHucpm96eVveoP2Faiup8Q"
              "=\n").decode("base64").decode("zip")
    
    assert (stream.getvalue() == result)


def test_docstruct():
    d = RootDoc("root")
    fill_doc(d)

    assert d.to_json() == {
        'content': [
            'foo', 
            'bar', 
            {'content': 
             [
                 'foobar', 
                 'foobarbar', 
                 {'content': 
                  [['n1', 'c2', 'test3'], 
                   '', 
                   ['1', '2', '3'], 
                   ['7', '5', '6'], 
                   ['6', '45648', '2'], 
                   '', 
                   ['aze', 'az', 'aa']], 
                  'type': 'table', 
                  'name': 'table 1'}], 
             'type': 'struct', 
             'name': 'sub1'}, 
            {'content': [ 'foobar', 'foobar',
                          {'content': ['abcdefghij\nklmnop'], 'type': 'raw', 'name': 'raw part'},
                          'foobartrain!', 
                          {'content': ['thing 1', 'thing 2', 'thing 3'], 'type': 'list', 'name': 'list of things'}, 
                          {'content': ['barfoo', 'barfoo', 'barfoo', 'barfoo'], 'type': 'struct', 'name': 'subsub3'}, 
                          'unpushed content of sub2..1', 
                          'unpushed content of sub2..2', 
                          'unpushed content of sub2..3'],
             'type': 'struct', 
             'name': 'sub2'}], 
        'type': 'struct', 
        'name': 'root'}


def test_formatter_rest():
    d = RootDoc("root")
    fill_doc(d)
    fmt = bta.formatters.rest.ReST()
    d.format_doc(fmt)
    output = fmt.finalize()
    result = ("eJx9Ue2KwyAQ/D9Psfc7JGBs0yPQhzGpaXLXaomGwhHu2etqP2nJIjvOOLq7iNFaj20IoLMWjRoB"
              "NzUCeYiosZSAdxnrecpPiJmMIJqpLYkYvXZe0oyM396m/ITBL6Iv2gPKhEHfRL6+6tVdryJfravV"
              "9+PeQj/qTxPn9I5Sy34euvw0NFAUNKpzXQNEqml3utv3w08gv4ejsaeb349qMF9BzugwOE+2I98P"
              "Zu9qcOk8MRIvrHxhMrYRlsR/CvCPXD/mHSZzmlyvd9Ra47WJNXmOohALZ+XCmbwAHi+NPA==").decode("base64").decode("zip")
    assert output == result

def test_formatter_raw():
    d = RootDoc("root")
    fill_doc(d)
    fmt = bta.formatters.raw.Raw()
    d.format_doc(fmt)
    output = fmt.finalize()
    assert output == "abcdefghij\nklmnop"


def test_formatter_raw_noinput():
    d = RootDoc("root")
    s = d.create_subsection("s1")
    s.add("qsd")
    t = s.create_table("tab")
    fmt = bta.formatters.raw.Raw()
    d.format_doc(fmt)
    output = fmt.finalize()
    assert output == ""

def test_formatter_rawzip_multiple_input():
    d = RootDoc("root")
    s = d.create_subsection("s1")
    s.add("qsd")
    t = s.create_table("tab")
    r = s.create_raw("raw1")
    r.add("abc")
    r.add("de\nfgh")
    r2 = s.create_raw("raw2")
    r2.add("ABC")
    r2.add("DE\nFGH")
    fmt = bta.formatters.rawzip.RawZip()
    d.format_doc(fmt)
    output = fmt.finalize()
    z = zipfile.ZipFile(StringIO.StringIO(output))
    assert len(z.infolist()) == 2
    f1,f2 = z.infolist()
    assert f1.filename == "raw1"
    assert f2.filename == "raw2"
    assert z.open(f1.filename).read() == "abcde\nfgh"
    assert z.open(f2.filename).read() == "ABCDE\nFGH"
