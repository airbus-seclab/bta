# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import pytest
import bta.miner
import bta.miners
import bta.backend
import argparse

bta.miners.import_all(stop_on_error=True)



class FakeBackend(bta.backend.Backend):
    def open_raw_table(self, name):
        return FakeTable()
    def open_virtual_table(self, name):
        return FakeTable()
    def open_special_table(self, name):
        return FakeTable()

class FakeTable(bta.backend.BackendTable):
    def count(self):
        return 1
    def find(self, *args, **kargs):
        return {}

@pytest.fixture(scope="module")
def fake_options():
    return argparse.Namespace()

@pytest.fixture(scope="module")
def fake_backend(fake_options):
    return FakeBackend(fake_options, "")


def test_all_miners_are_loaded():
    loaded_miners_nb = len(bta.miner.MinerRegistry.get_all())
    assert  loaded_miners_nb >= 30

def test_all_miners_create_subparser():
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest='miner_name', help="Miners")
    for miner in bta.miner.MinerRegistry.itervalues():
        p = subparser.add_parser(miner._name_, help=miner._desc_)
        miner.create_arg_subparser(p)


def test_all_miners_instantiate(fake_backend, fake_options):
    for miner in bta.miner.MinerRegistry.itervalues():
        miner(fake_backend)
