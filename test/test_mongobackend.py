
import pytest
from bta.backend.mongo import *
from bta.tools.expr import Field
import argparse
from miner_helpers import normal_db


@pytest.fixture
def backend(normal_db):
    options = argparse.Namespace(verbose=0)
    backend = bta.backend.mongo.Mongo(options, database=normal_db)
    return backend

def test_mongo_backend(backend, normal_db):
    datatable = backend.open_raw_table("datatable")
    assert datatable.count() == normal_db.datatable.count()
    assert list(datatable.find({"PDNT_col" : 7263})) == list(normal_db.datatable.find({"PDNT_col" : 7263}))
    

def test_mongo_datasd(backend, normal_db):
    datasd = backend.open_virtual_table("datasd")
    res = list(datasd.find(Field("PDNT_col")==7263))
    assert len(res) == 1
    assert res[0]["PDNT_col"] == 7263
    assert "sd_id" in res[0]
    sdid = res[0]["sd_id"]
    res = list(datasd.find(Field("sd_id")==0xdead))
    assert len(res) == 0
    res = list(datasd.find(Field("sd_id")==sdid))
    assert len(res) > 0
    assert res[0]["sd_id"] == sdid
    assert 7263 in [x["PDNT_col"] for x in res]
    
