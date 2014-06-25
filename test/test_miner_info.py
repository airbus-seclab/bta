# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import pytest

import bta.miners.info

from miner_helpers import run_miner, normal_db


def test_miner_info(normal_db):
    out = run_miner(bta.miners.info.Info, normal_db)
    expected = { 'content': [ {'content': ['Data format version: 1', 
                                           {'content': [('name', 'number of records'), 
                                                        None, ('category', normal_db.category.count()), 
                                                        ('datatable_meta', normal_db.datatable_meta.count()), 
                                                        ('log', normal_db.log.count()), 
                                                        ('link_table', normal_db.link_table.count()), 
                                                        ('sd_table', normal_db.sd_table.count()), 
                                                        ('metadata', normal_db.metadata.count()),
                                                        ('usersid', normal_db.usersid.count()), 
                                                        ('dnames', normal_db.dnames.count()), 
                                                        ('domains', normal_db.domains.count()), 
                                                        ('guid', normal_db.guid.count()), 
                                                        ('datatable', normal_db.datatable.count()), 
                                                        ('system.indexes', normal_db.system.indexes.count()), 
                                                    ], 
                                            'type': 'table', 
                                            'name': 'collections'}], 
                               'type': 'struct', 
                               'name': 'collections in this database' }, 
                              {'content': [ 
                                  {'content': ["2014-01-27 17:51:49: ['/tmp/vbta/bin/ntds2db', '-C', '::test', '/tmp/ntds.dit']", 
                                               {'content': [
                                                   '2014-01-27 17:51:49: Opened ESEDB file [/tmp/ntds.dit]',
                                                   '2014-01-27 17:51:49: Start of importation of [sd_table]',
                                                   '2014-01-27 17:51:49: End of importation of [sd_table]. 94 records.'
                                               ], 
                                                'type': 'list',
                                                'name': 'actions'}
                                           ], 
                                   'type': 'list', 
                                   'name': 'logs' } ],
                               'type': 'struct',
                               'name': 'logs' }, 
                              { 'content': [
                                  {'content': [
                                      ('number of records', normal_db.datatable.count()), 
                                      ('number of columns', normal_db.datatable_meta.count())], 
                                   'type': 'table',
                                   'name': 'datatable'}, 
                                  {'content': [('number of records', normal_db.sd_table.count())], 
                                   'type': 'table', 
                                   'name': 'sd_table'}, 
                                  {'content': [('number of records', normal_db.link_table.count())], 
                                   'type': 'table', 
                                   'name': 'link_table'}], 
                                'type': 'struct', 
                                'name': 'tables'}], 
                 'type': 'struct', 
                 'name': 'test'}
    assert repr(out.to_json()) == repr(expected)
    assert out.to_json() == expected

