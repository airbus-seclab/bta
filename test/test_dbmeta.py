# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

""" Test DBMetadataEntry class """

from bta import dbmeta
from bta.backend import mongo
import collections
import pytest


@pytest.fixture(scope="module")
def dbmetaentry(request):
    optdict = {"overwrite": True}
    backend_class = collections.namedtuple('Options', optdict.keys())
    options = backend_class(*optdict.values())
    backend = mongo.Backend.get_backend("mongo")(options, "::test")
    # Drop & create table
    backend.open_table("metadata").create()
    dbmetaentry = dbmeta.DBMetadataEntry(backend)
    def tear_down():
        backend.cnx.drop_database(backend.db)
    request.addfinalizer(tear_down)
    return dbmetaentry

def test_00_read_absent_value(dbmetaentry):
    val = dbmetaentry.get_value("importer_version")
    assert val == None

def test_01_insert_read_new_entry(dbmetaentry):
    # insert new entry
    dbmetaentry.set_value("importer_version", 2)

    # read entry
    val = dbmetaentry.get_value("importer_version")
    assert val == 2

def test_02_update_read_entry(dbmetaentry):
    # update entry
    dbmetaentry.set_value("importer_version", 42)

    # read updated data
    val = dbmetaentry.get_value("importer_version")
    assert val == 42
