# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

""" Test DBMetadataEntry class """

from bta import dbmeta
import bta.backend.mongo
import collections
import pytest
import argparse
from miner_helpers import normal_db


@pytest.fixture(scope="module")
def dbmetaentry(normal_db):
    options = argparse.Namespace(verbose=0)
    backend = bta.backend.mongo.Mongo(options, database=normal_db)
    dbmetaentry = dbmeta.DBMetadataEntry(backend)
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
