# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import pytest
from bta.docstruct import *
import StringIO

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
    s2.add("foobartrain!")
    t.add(["6","45648","2"])
    t.add("")
    t.add(["aze","az","aa"])
    t.finished()
    s1.finished()
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

    result = ("eJytks8OgjAMh++/p5hXjSYbf/TiwwwcQkI2w8aF+PCWgR6gEg82JG2+Lu0Xt"
              "s65gCsFUDmHQneA7wuJI0VkI5pSbAZdtEZIwEqxjqcoFYuD8SFZ0LhjFQeWfs"
              "HgJGgdJ0F4aRAtzvzZjMc5N4KDdDbN8vTym9w//oUeDGehB1ZOa8YC8fYVd/t"
              "zCp1u7A5oGx+Eq0SoG3v3wH6q6GW8K/WpkmksfVTRjPmlrRN6++h9bW6idDYY"
              "GzeMQqeT3Oipjd64+wV4mZ3f").decode("base64").decode("zip")
    
    assert (stream.getvalue() == result)


def test_docstruct():
    d = RootDoc("root")
    fill_doc(d)

    print d.to_json()
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
            {'content': [ 'foobar', 'foobar', 'foobartrain!', 
                          {'content': ['thing 1', 'thing 2', 'thing 3'], 'type': 'list', 'name': 'list of things'}, 
                          {'content': ['barfoo', 'barfoo', 'barfoo', 'barfoo'], 'type': 'struct', 'name': 'subsub3'}, 
                          'unpushed content of sub2..1', 
                          'unpushed content of sub2..2', 
                          'unpushed content of sub2..3'],
             'type': 'struct', 
             'name': 'sub2'}], 
        'type': 'struct', 
        'name': 'root'}
