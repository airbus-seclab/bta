# -*- coding: utf-8 -*-
# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

import pytest

import bta.miners.check_UAC

from miner_helpers import run_miner, normal_db


def test_miner_check_UAC_normal_account(normal_db):
    out = run_miner(bta.miners.check_UAC.CheckUAC, normal_db, flags=["normalAccount"])
    assert out.to_json() == {
        "content": [
            {
                "content": [
                    [ "cn",  "SID",  "Flags" ], 
                    [], 
                    [ "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042", "S-1-5-21-1154669122-758131934-2550385761-1125", 
                      "normalAccount, accountDisable" ], 
                    [ "krbtgt", "S-1-5-21-1154669122-758131934-2550385761-502", "normalAccount, accountDisable" ], 
                    [ "auditor", "S-1-5-21-1154669122-758131934-2550385761-1151", "normalAccount" ], 
                    [ "SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}", "S-1-5-21-1154669122-758131934-2550385761-1121", 
                      "normalAccount, accountDisable" ], 
                    [ "Administrateur", "S-1-5-21-1154669122-758131934-2550385761-500", "normalAccount" ], 
                    [ "intru", "S-1-5-21-1154669122-758131934-2550385761-1000", "normalAccount, passwdNotrequired" ], 
                    [ "jean dupond", "S-1-5-21-1154669122-758131934-2550385761-1153", "normalAccount" ], 
                    [ "Invité", "S-1-5-21-1154669122-758131934-2550385761-501", 
                      "normalAccount, dontExpirePassword, accountDisable, passwdNotrequired" ], 
                    [ "DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}", "S-1-5-21-1154669122-758131934-2550385761-1123", 
                      "normalAccount, accountDisable" ], 
                    [ "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}", "S-1-5-21-1154669122-758131934-2550385761-1122",
                      "normalAccount, accountDisable" ]
                ], 
                "type": "table", 
                "name": "Weird account rights with all flags: normalAccount"
            }
        ], 
        "type": "struct", 
        "name": "test"
    }


def test_miner_check_UAC_account_disable(normal_db):
    out = run_miner(bta.miners.check_UAC.CheckUAC, normal_db, flags=["accountDisable"])
    assert out.to_json() == {
        "content": [
            {
                "content": [
                    [ "cn",  "SID",  "Flags" ], 
                    [], 
                    [ "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042", "S-1-5-21-1154669122-758131934-2550385761-1125", 
                      "normalAccount, accountDisable" ], 
                    [ "krbtgt", "S-1-5-21-1154669122-758131934-2550385761-502", "normalAccount, accountDisable" ], 
                    [ "SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}", "S-1-5-21-1154669122-758131934-2550385761-1121", 
                      "normalAccount, accountDisable" ], 
                    [ "Invité", "S-1-5-21-1154669122-758131934-2550385761-501", 
                      "normalAccount, dontExpirePassword, accountDisable, passwdNotrequired" ], 
                    [ "DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}", "S-1-5-21-1154669122-758131934-2550385761-1123", 
                      "normalAccount, accountDisable" ], 
                    [ "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}", "S-1-5-21-1154669122-758131934-2550385761-1122",
                      "normalAccount, accountDisable" ]
                ], 
                "type": "table", 
                "name": "Weird account rights with all flags: accountDisable"
            }
        ], 
        "type": "struct", 
        "name": "test"
    }


def test_miner_check_UAC_account_disable_password_not_requered(normal_db):
    out = run_miner(bta.miners.check_UAC.CheckUAC, normal_db, flags=["accountDisable", "passwdNotrequired"])
    assert out.to_json() == {
        "content": [
            {
                "content": [
                    [ "cn",  "SID",  "Flags" ], 
                    [], 
                    [ "Invité", "S-1-5-21-1154669122-758131934-2550385761-501", 
                      "normalAccount, dontExpirePassword, accountDisable, passwdNotrequired" ], 
                ], 
                "type": "table", 
                "name": "Weird account rights with all flags: accountDisable, passwdNotrequired"
            }
        ], 
        "type": "struct", 
        "name": "test"
    }

