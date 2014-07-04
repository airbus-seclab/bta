# -*- coding: utf-8 -*-

# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity



import pytest
import mongomock
from mongomock import ObjectId
import json
import argparse
import datetime
import dateutil.parser
import bta.docstruct
import bta.backend.mongo


def Date(x):
    return datetime.datetime.fromtimestamp(x/1000)

def ISODate(x):
    return dateutil.parser.parse(x)

def NumberLong(x):
    return x

false = False
true = True


## Helpers


def run_miner(miner, db, **kargs):
    options = argparse.Namespace(verbose=0,**kargs)
    doc = bta.docstruct.RootDoc("test")
    backend = bta.backend.mongo.Mongo(options, database=db)
    m = miner(backend)
    m.run(options, doc)
    return doc


## Fixtures

@pytest.fixture(scope="session")
def normal_db():
    cnx = mongomock.Connection()
    db = cnx.db
    db.log.insert( 
        { "_id" : ObjectId( "6426f8ea2c4f057c661f2c3d" ), 
          "actions" : [ { "date" : Date( 1390841509307 ), "action" : "Opened ESEDB file [/tmp/ntds.dit]" }, 
                        { "date" : Date( 1390841509307 ), "action" : "Start of importation of [sd_table]" }, 
                        { "date" : Date( 1390841509385 ), "action" : "End of importation of [sd_table]. 94 records." }, ], 
          "args" : [ "/tmp/vbta/bin/ntds2db", "-C", "::test", "/tmp/ntds.dit" ], 
          "date" : Date( 1390841509288 ), 
          "program" : "/tmp/vbta/bin/ntds2db", 
          "version" : "0.3" })


    db.category.insert({"id" : 6,    "name" : "Organization"})
    db.category.insert({"id" : 1369, "name" : "Person"  })
    db.category.insert({"id" : 1363, "name" : "Computer" })

    db.guid.insert({ "id" : "bf967aa3-0de6-11d0-a285-00aa003049e2", "name" : "Organization" })
    db.guid.insert({ "id" : "f0f8ffab-1191-11d0-a060-00aa006c33ed", "name" : "NTDS-DSA" })
    db.guid.insert({ "id" : "bf967a8f-0de6-11d0-a285-00aa003049e2", "name" : "DMD" })
    db.guid.insert({ "id" : "5a8b3261-c38d-11d1-bbc9-0080c76670c0", "name" : "SubSchema" })

    db.domains.insert({"domain" : ".intra.secu.labz", "sid" : "S-1-5-21-1154669122-758131934-2550385761" })

    db.dnames.insert({ "DName" : "", "name" : "$ROOT_OBJECT$", "DNT_col" : 2 })
    db.dnames.insert({ "DName" : "CN=Organization,CN=Schema,CN=Configuration,DC=labz,DC=secu,DC=intra", "name" : "Organization", "DNT_col" : 6 })
    db.dnames.insert({ "DName" : "CN=Aggregate,CN=Schema,CN=Configuration,DC=labz,DC=secu,DC=intra", "name" : "Aggregate", "DNT_col" : 11 })
    db.dnames.insert({ "DName" : "DC=intra", "name" : "intra", "DNT_col" : 1787 })
    db.dnames.insert({ "DName" : "DC=secu,DC=intra", "name" : "secu", "DNT_col" : 1788 })
    db.dnames.insert({ "DName" : "CN=NTDS-DSA,CN=Schema,CN=Configuration,DC=labz,DC=secu,DC=intra", "name" : "NTDS-DSA", "DNT_col" : 8 })
    db.dnames.insert({ "DName" : "CN=DMD,CN=Schema,CN=Configuration,DC=labz,DC=secu,DC=intra", "name" : "DMD", "DNT_col" : 10 })
    db.dnames.insert({ "DName" : "CN=SubSchema,CN=Schema,CN=Configuration,DC=labz,DC=secu,DC=intra", "name" : "SubSchema", "DNT_col" : 12 })
    db.dnames.insert({ "DName" : "CN=Account-Expires,CN=Schema,CN=Configuration,DC=labz,DC=secu,DC=intra", "name" : "Account-Expires", "DNT_col" : 13 })

    db.usersid.insert({ "account" : "Administrateur", "name" : "Administrateur", "sid" : "S-1-5-21-1154669122-758131934-2550385761-500" })
    db.usersid.insert({ "account" : "Invité", "name" : "Invité", "sid" : "S-1-5-21-1154669122-758131934-2550385761-501" })
    db.usersid.insert({ "account" : "intru", "name" : "intru", "sid" : "S-1-5-21-1154669122-758131934-2550385761-1000" })
    db.usersid.insert({ "account" : "krbtgt", "name" : "krbtgt", "sid" : "S-1-5-21-1154669122-758131934-2550385761-502" })
    db.usersid.insert({ "account" : "SM_58dd3f44226c42659", "name" : "SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}", "sid" : "S-1-5-21-1154669122-758131934-2550385761-1121" })
    db.usersid.insert({ "account" : "SM_a071a1d498164d9ba", "name" : "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}", "sid" : "S-1-5-21-1154669122-758131934-2550385761-1122" })
    db.usersid.insert({ "account" : "SM_2054380de59c4bfe9", "name" : "DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}", "sid" : "S-1-5-21-1154669122-758131934-2550385761-1123" })
    db.usersid.insert({ "account" : "SM_142594fac6dc446f9", "name" : "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042", "sid" : "S-1-5-21-1154669122-758131934-2550385761-1125" })
    db.usersid.insert({ "account" : "auditor", "name" : "auditor", "sid" : "S-1-5-21-1154669122-758131934-2550385761-1151" })
    db.usersid.insert({ "account" : "jdupond", "name" : "jean dupond", "sid" : "S-1-5-21-1154669122-758131934-2550385761-1153" })

    db.datatable.insert({
	"_id" : ObjectId("53849cefe64f050c8f16960c"),
	"mailNickname" : "Administrateur",
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 1,
	"cn" : "Administrateur",
	"msExchPoliciesIncluded" : [
		"{26491cfc-9e50-4857-861b-0cb8df22b5d7}",
		"7c5b6d1b-0f29-4f59-9779-67b2860ddb2b"
	],
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"userPrincipalName" : "Administrateur@labz.secu.intra",
	"msExchUMDtmfMap" : [
		"firstNameLastName:23646478728387",
		"lastNameFirstName:23646478728387",
		"emailAddress:23646478728387"
	],
	"msExchRecipientDisplayType" : 1073741824,
	"instanceType" : 4,
	"DNT_col" : 3563,
	"sAMAccountName" : "Administrateur",
	"distinguishedName" : 3563,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T00:09:21Z"),
		ISODate("2011-12-20T00:20:04Z"),
		ISODate("2011-12-20T01:12:49Z"),
		ISODate("2011-12-20T01:26:18Z"),
		ISODate("2011-12-23T18:34:48Z")
	],
	"OBJ_col" : 1,
	"msExchMailboxSecurityDescriptor" : 267,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"msExchHomeServerName" : "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=EXCHANGE",
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-500",
	"whenCreated" : ISODate("2011-12-19T18:54:49Z"),
	"uSNCreated" : 8196,
	"legacyExchangeDN" : "漯䘽物瑳传杲湡穩瑡潩⽮畯䔽捸慨杮⁥摁業楮瑳慲楴敶䜠潲灵⠠奆䥄佂䙈㌲偓䱄⥔振㵮敒楣楰湥獴振㵮摁業楮瑳慲整牵",
	"mail" : "Administrateur@labz.secu.intra",
	"PDNT_col" : 7263,
	"nTSecurityDescriptor" : 229,
	"objectCategory" : 1369,
	"homeMTA" : 7913,
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		7263,
		3563
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-19T18:54:49Z"),
	"proxyAddresses" : "SMTP:Administrateur@labz.secu.intra",
	"cnt_col" : 15,
	"objectGUID" : "9f0c16dd-9c00-44dd-a3e4-0282cfd01a65",
	"whenChanged" : ISODate("2013-02-04T00:00:28Z"),
	"RDNtyp_col" : 3,
	"displayName" : "Administrateur",
	"name" : "Administrateur",
	"msExchRecipientTypeDetails" : 1,
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : false,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : false,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 512
	},
	"msExchWhenMailboxCreated" : ISODate("2011-12-20T00:42:06Z"),
	"sAMAccountType" : 805306368,
	"uSNChanged" : 106532,
	"msExchVersion" : NumberLong("44220983382016"),
    })
    db.datatable.insert({
	"_id" : ObjectId("53849cefe64f050c8f16960d"),
	"primaryGroupID" : 514,
	"IsVisibleInAB" : 42,
	"cn" : "Invité",
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"instanceType" : 4,
	"DNT_col" : 3564,
	"sAMAccountName" : "Invité",
	"distinguishedName" : 3564,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T00:13:38Z"),
		ISODate("2011-12-20T00:20:04Z"),
		ISODate("2011-12-23T18:34:48Z")
	],
	"OBJ_col" : 1,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-501",
	"whenCreated" : ISODate("2011-12-19T18:54:50Z"),
	"uSNCreated" : 8197,
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 416,
	"objectCategory" : 1369,
	"objectGUID" : "78011bc0-0a8b-4d97-a6e1-f7c73d4d5967",
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		3564
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-19T18:54:50Z"),
	"cnt_col" : 2,
	"whenChanged" : ISODate("2011-12-19T18:54:50Z"),
	"RDNtyp_col" : 3,
	"name" : "Invité",
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : true,
			"tempDuplicateAccount" : false,
			"accountDisable" : true,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : true,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 66082
	},
	"sAMAccountType" : 805306368,
	"uSNChanged" : 8197,
	"accountExpires" : ISODate("1970-01-01T01:00:00Z")
    })
    db.datatable.insert({
	"_id" : ObjectId("53849cefe64f050c8f16960e"),
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 42,
	"cn" : "intru",
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"instanceType" : 4,
	"DNT_col" : 3565,
	"distinguishedName" : 3565,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T00:09:21Z"),
		ISODate("2011-12-19T19:11:30Z"),
		ISODate("2011-12-20T00:20:04Z"),
		ISODate("2011-12-20T01:12:49Z"),
		ISODate("2011-12-23T18:34:48Z")
	],
	"OBJ_col" : 1,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-1000",
	"whenCreated" : ISODate("2011-12-19T18:54:50Z"),
	"uSNCreated" : 8198,
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 229,
	"sAMAccountName" : "intru",
	"objectCategory" : 1369,
	"objectGUID" : "c0dd7381-b937-48a8-9208-04917a506d58",
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		3565
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-19T18:54:50Z"),
	"cnt_col" : 3,
	"whenChanged" : ISODate("2011-12-20T01:12:49Z"),
	"RDNtyp_col" : 3,
	"name" : "intru",
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : false,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : true,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 544
	},
	"sAMAccountType" : 805306368,
	"uSNChanged" : 27028
    })
    db.datatable.insert({
	"_id" : ObjectId("53849cf0e64f050c8f16963c"),
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 42,
	"cn" : "krbtgt",
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"instanceType" : 4,
	"DNT_col" : 3611,
	"sAMAccountName" : "krbtgt",
	"distinguishedName" : 3611,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T00:09:21Z"),
		ISODate("2011-12-19T19:11:30Z"),
		ISODate("2011-12-20T00:20:04Z"),
		ISODate("2011-12-20T01:12:49Z"),
		ISODate("2011-12-23T18:34:48Z")
	],
	"OBJ_col" : 1,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-502",
	"whenCreated" : ISODate("2011-12-19T18:56:20Z"),
	"uSNCreated" : 12324,
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 229,
	"objectCategory" : 1369,
	"objectGUID" : "f82bfa3f-8af3-4ee1-a685-cebb96662297",
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		3611
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-19T18:56:20Z"),
	"cnt_col" : 2,
	"whenChanged" : ISODate("2011-12-20T01:12:49Z"),
	"RDNtyp_col" : 3,
	"name" : "krbtgt",
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : true,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : false,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 514
	},
	"sAMAccountType" : 805306368,
	"uSNChanged" : 27039,
	"accountExpires" : ISODate("1970-01-01T01:00:00Z")
    })
    db.datatable.insert({
	"_id" : ObjectId("53849d16e64f050c8f16a257"),
	"mailNickname" : "SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}",
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 1,
	"cn" : "SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}",
	"msExchPoliciesIncluded" : [
		"{26491cfc-9e50-4857-861b-0cb8df22b5d7}",
		"7c5b6d1b-0f29-4f59-9779-67b2860ddb2b"
	],
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"userPrincipalName" : "SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}@labz.secu.intra",
	"msExchUMDtmfMap" : [
		"firstNameLastName:6739242777682513052927323243292203259333256342",
		"lastNameFirstName:6739242777682513052927323243292203259333256342",
		"emailAddress:797836624526913052927343044529330020139680927"
	],
	"msExchModerationFlags" : 6,
	"msExchHideFromAddressLists" : 1,
	"msExchAddressBookFlags" : 1,
	"msExchRecipientDisplayType" : 10,
	"instanceType" : 4,
	"DNT_col" : 7541,
	"distinguishedName" : 7541,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T18:21:38Z"),
		ISODate("2011-12-20T00:19:52Z"),
		ISODate("2011-12-20T00:20:04Z"),
		ISODate("2011-12-20T00:42:07Z"),
		ISODate("2011-12-23T18:34:48Z")
	],
	"OBJ_col" : 1,
	"msExchMailboxSecurityDescriptor" : 268,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"msExchHomeServerName" : "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=EXCHANGE",
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-1121",
	"whenCreated" : ISODate("2011-12-20T00:19:52Z"),
	"uSNCreated" : 25882,
	"legacyExchangeDN" : "漯䘽物瑳传杲湡穩瑡潩⽮畯䔽捸慨杮⁥摁業楮瑳慲楴敶䜠潲灵⠠奆䥄佂䙈㌲偓䱄⥔振㵮敒楣楰湥獴振㵮祓瑳浥慍汩潢筸昱㔰㥡㜲攭搴ⴰ㐴㈵㤭摦ⴰ",
	"mail" : "SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}@labz.secu.intra",
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 415,
	"sAMAccountName" : "SM_58dd3f44226c42659",
	"objectCategory" : 1369,
	"homeMTA" : 7913,
	"objectGUID" : "643c6745-55c3-48dc-a827-4c178acb5500",
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		7541
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-20T00:19:52Z"),
	"proxyAddresses" : "SMTP:SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}@labz.secu.intra",
	"msExchUserAccountControl" : 2,
	"cnt_col" : 1,
	"whenChanged" : ISODate("2011-12-20T00:42:07Z"),
	"RDNtyp_col" : 3,
	"displayName" : "Assistant Approbation de Microsoft Exchange",
	"name" : "SystemMailbox{1f05a927-e4d0-4452-9fd0-0201e96809a7}",
	"msExchUMEnabledFlags2" : -1,
	"msExchMailboxAuditLogAgeLimit" : 7776000,
	"msExchRecipientTypeDetails" : 8388608,
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : true,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : false,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 514
	},
	"msExchWhenMailboxCreated" : ISODate("2011-12-20T00:42:07Z"),
	"sAMAccountType" : 805306368,
	"uSNChanged" : 26945,
	"sn" : "MSExchApproval 1f05a927-3be2-4fb9-aa03-b59fe3b56f4c",
	"msExchVersion" : NumberLong("1126140425011200"),
	"accountExpires" : ISODate("1970-01-01T01:00:00Z")
    })
    db.datatable.insert({
	"_id" : ObjectId("53849d16e64f050c8f16a258"),
	"mailNickname" : "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}",
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 1,
	"cn" : "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}",
	"msExchPoliciesIncluded" : [
		"{26491cfc-9e50-4857-861b-0cb8df22b5d7}",
		"7c5b6d1b-0f29-4f59-9779-67b2860ddb2b"
	],
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"userPrincipalName" : "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@labz.secu.intra",
	"msExchUMDtmfMap" : [
		"firstNameLastName:67392434726837930321229892340342678362293823339",
		"lastNameFirstName:67392434726837930321229892340342678362293823339",
		"emailAddress:797836624526930321229892340342678362293823339"
	],
	"msExchModerationFlags" : 6,
	"msExchHideFromAddressLists" : 1,
	"msExchAddressBookFlags" : 1,
	"msExchRecipientDisplayType" : 10,
	"instanceType" : 4,
	"DNT_col" : 7542,
	"distinguishedName" : 7542,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T18:21:38Z"),
		ISODate("2011-12-20T00:19:52Z"),
		ISODate("2011-12-20T00:20:04Z"),
		ISODate("2011-12-20T00:42:08Z"),
		ISODate("2011-12-23T18:34:48Z")
	],
	"OBJ_col" : 1,
	"msExchMailboxSecurityDescriptor" : 268,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"msExchHomeServerName" : "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=EXCHANGE",
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-1122",
	"whenCreated" : ISODate("2011-12-20T00:19:52Z"),
	"uSNCreated" : 25887,
	"legacyExchangeDN" : "漯䘽物瑳传杲湡穩瑡潩⽮畯䔽捸慨杮⁥摁業楮瑳慲楴敶䜠潲灵⠠奆䥄佂䙈㌲偓䱄⥔振㵮敒楣楰湥獴振㵮祓瑳浥慍汩潢筸づ捤挱㤲㠭挹ⴳ〴㐳戭㜶ⴸ",
	"mail" : "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@labz.secu.intra",
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 415,
	"sAMAccountName" : "SM_a071a1d498164d9ba",
	"objectCategory" : 1369,
	"homeMTA" : 7913,
	"objectGUID" : "aab967de-7cd8-4df4-b210-9d9c96ef1219",
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		7542
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-20T00:19:52Z"),
	"proxyAddresses" : "SMTP:SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@labz.secu.intra",
	"msExchUserAccountControl" : 2,
	"cnt_col" : 1,
	"whenChanged" : ISODate("2011-12-20T00:43:11Z"),
	"RDNtyp_col" : 3,
	"displayName" : "Microsoft Exchange",
	"name" : "SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}",
	"msExchUMEnabledFlags2" : -1,
	"msExchMailboxAuditLogAgeLimit" : 7776000,
	"msExchRecipientTypeDetails" : 8388608,
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : true,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : false,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 514
	},
	"msExchWhenMailboxCreated" : ISODate("2011-12-20T00:42:08Z"),
	"sAMAccountType" : 805306368,
	"uSNChanged" : 26963,
	"sn" : "MsExchDiscovery e0dc1c29-89c3-4034-b678-e6c29d823ed9",
	"msExchVersion" : NumberLong("1126140425011200"),
	"accountExpires" : ISODate("1970-01-01T01:00:00Z")
    })
    db.datatable.insert({
	"_id" : ObjectId("53849d16e64f050c8f16a259"),
	"mailNickname" : "DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}",
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 1,
	"objectGUID" : "c190fa19-a8f7-49da-a16c-f9e2fe0d9b89",
	"cn" : "DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}",
	"msExchPoliciesIncluded" : [
		"{26491cfc-9e50-4857-861b-0cb8df22b5d7}",
		"7c5b6d1b-0f29-4f59-9779-67b2860ddb2b"
	],
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"userPrincipalName" : "DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}@labz.secu.intra",
	"msExchUMDtmfMap" : [
		"firstNameLastName:673924347268379624526939192205462641538023730933422852",
		"lastNameFirstName:673924347268379624526939192205462641538023730933422852",
		"emailAddress:347268379732724624526939192205462641538023730933422852"
	],
	"msExchModerationFlags" : 6,
	"msExchHideFromAddressLists" : 1,
	"msExchAddressBookFlags" : 1,
	"instanceType" : 4,
	"DNT_col" : 7543,
	"distinguishedName" : 7543,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T00:13:38Z"),
		ISODate("2011-12-20T00:19:52Z"),
		ISODate("2011-12-20T00:20:04Z"),
		ISODate("2011-12-23T18:34:48Z")
	],
	"OBJ_col" : 1,
	"mDBOverHardQuotaLimit" : 52428800,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"msExchHomeServerName" : "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=EXCHANGE",
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-1123",
	"whenCreated" : ISODate("2011-12-20T00:19:52Z"),
	"uSNCreated" : 25892,
	"mDBOverQuotaLimit" : 52428800,
	"legacyExchangeDN" : "漯䘽物瑳传杲湡穩瑡潩⽮畯䔽捸慨杮⁥摁業楮瑳慲楴敶䜠潲灵⠠奆䥄佂䙈㌲偓䱄⥔振㵮敒楣楰湥獴振㵮楄捳癯牥卹慥捲䵨楡扬硯笠㥄㤱䅂㔰㐭䄶ⴶ",
	"mail" : "DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@labz.secu.intra",
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 412,
	"sAMAccountName" : "SM_2054380de59c4bfe9",
	"objectCategory" : 1369,
	"homeMTA" : 7913,
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		7543
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-20T00:19:52Z"),
	"proxyAddresses" : "SMTP:DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}@labz.secu.intra",
	"msExchUserAccountControl" : 2,
	"cnt_col" : 2,
	"msExchMailboxSecurityDescriptor" : 270,
	"whenChanged" : ISODate("2011-12-20T00:43:01Z"),
	"RDNtyp_col" : 3,
	"displayName" : "Boîte aux lettres de détection",
	"name" : "DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB852}",
	"msExchUMEnabledFlags2" : -1,
	"msExchMailboxAuditLogAgeLimit" : 7776000,
	"msExchRecipientTypeDetails" : 536870912,
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : true,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : false,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 514
	},
	"msExchWhenMailboxCreated" : ISODate("2011-12-20T00:42:08Z"),
	"sAMAccountType" : 805306368,
	"uSNChanged" : 26960,
	"sn" : "MsExchDiscoveryMailbox D919BA05-46A6-415f-80AD-7E09334BB852",
	"msExchVersion" : NumberLong("1126140425011200"),
	"accountExpires" : ISODate("1970-01-01T01:00:00Z")
    })
    db.datatable.insert({
	"_id" : ObjectId("53849d16e64f050c8f16a25a"),
	"mailNickname" : "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042",
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 1,
	"cn" : "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042",
	"msExchPoliciesIncluded" : [
		"{26491cfc-9e50-4857-861b-0cb8df22b5d7}",
		"7c5b6d1b-0f29-4f59-9779-67b2860ddb2b"
	],
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"msExchMessageHygieneSCLDeleteThreshold" : 9,
	"userPrincipalName" : "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@labz.secu.intra",
	"msExchUMDtmfMap" : [
		"firstNameLastName:3333728333624542134382817941489323002953213042",
		"lastNameFirstName:3333728333624542134382817941489323002953213042",
		"emailAddress:3333728333624542134382817941489323002953213042"
	],
	"msExchModerationFlags" : 6,
	"msExchHideFromAddressLists" : 1,
	"msExchAddressBookFlags" : 1,
	"msExchRecipientDisplayType" : 10,
	"msExchMessageHygieneSCLJunkThreshold" : 4,
	"mDBStorageQuota" : 1024,
	"instanceType" : 4,
	"DNT_col" : 7545,
	"distinguishedName" : 7545,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T18:21:38Z"),
		ISODate("2011-12-20T00:19:54Z"),
		ISODate("2011-12-20T00:20:04Z"),
		ISODate("2011-12-20T00:42:08Z"),
		ISODate("2011-12-23T18:34:48Z")
	],
	"OBJ_col" : 1,
	"msExchMailboxSecurityDescriptor" : 268,
	"mDBOverHardQuotaLimit" : 1024,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"msExchHomeServerName" : "/o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=EXCHANGE",
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-1125",
	"whenCreated" : ISODate("2011-12-20T00:19:54Z"),
	"uSNCreated" : 25898,
	"msExchMessageHygieneSCLRejectThreshold" : 7,
	"mDBOverQuotaLimit" : 1024,
	"legacyExchangeDN" : "漯䘽物瑳传杲湡穩瑡潩⽮畯䔽捸慨杮⁥摁業楮瑳慲楴敶䜠潲灵⠠奆䥄佂䙈㌲偓䱄⥔振㵮敒楣楰湥獴振㵮敆敤慲整䕤慭汩㐮ㅣ㑦㡤ⵢㄸ㤷㐭㐱ⴸ㌹晢",
	"mail" : "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@labz.secu.intra",
	"msExchMessageHygieneSCLQuarantineThreshold" : 9,
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 415,
	"sAMAccountName" : "SM_142594fac6dc446f9",
	"objectCategory" : 1369,
	"homeMTA" : 7913,
	"objectGUID" : "43eebb30-805f-4f6d-a024-750494aa3aeb",
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		7545
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-20T00:19:54Z"),
	"proxyAddresses" : "SMTP:FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@labz.secu.intra",
	"msExchUserAccountControl" : 2,
	"cnt_col" : 1,
	"whenChanged" : ISODate("2011-12-20T15:17:32Z"),
	"RDNtyp_col" : 3,
	"displayName" : "Microsoft Exchange Federation Mailbox",
	"name" : "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042",
	"msExchUMEnabledFlags2" : -1,
	"msExchMailboxAuditLogAgeLimit" : 7776000,
	"msExchRecipientTypeDetails" : 8388608,
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : true,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : false,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 514
	},
	"msExchWhenMailboxCreated" : ISODate("2011-12-20T00:42:08Z"),
	"sAMAccountType" : 805306368,
	"uSNChanged" : 27196,
	"sn" : "FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042",
	"msExchVersion" : NumberLong("1126140425011200"),
	"accountExpires" : ISODate("1970-01-01T01:00:00Z")
    })
    db.datatable.insert({
	"_id" : ObjectId("53849d25e64f050c8f16a6f7"),
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 1,
	"cn" : "auditor",
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"instanceType" : 4,
	"DNT_col" : 8777,
	"distinguishedName" : 8777,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T00:09:21Z"),
		ISODate("2011-12-26T16:42:29Z")
	],
	"OBJ_col" : 1,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-1151",
	"whenCreated" : ISODate("2011-12-26T16:42:28Z"),
	"uSNCreated" : 41009,
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 423,
	"sAMAccountName" : "auditor",
	"objectCategory" : 1369,
	"objectGUID" : "04374c3c-51a7-4731-99f3-292e73ecb3f5",
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		8777
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2011-12-26T16:42:28Z"),
	"cnt_col" : 1,
	"whenChanged" : ISODate("2011-12-26T16:42:29Z"),
	"RDNtyp_col" : 3,
	"displayName" : "auditor",
	"name" : "auditor",
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : false,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : false,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 512
	},
	"sAMAccountType" : 805306368,
	"uSNChanged" : 41015,
	"accountExpires" : ISODate("1970-01-01T01:00:00Z")
    })
    db.datatable.insert({
	"_id" : ObjectId("53849d25e64f050c8f16a702"),
	"primaryGroupID" : 513,
	"IsVisibleInAB" : 1,
	"cn" : "jean dupond",
	"objectClass" : [
		"1.2.840.113556.1.5.9",
		"2.5.6.7",
		"2.5.6.6",
		"2.5.6.0"
	],
	"instanceType" : 4,
	"DNT_col" : 8788,
	"distinguishedName" : 8788,
	"dSCorePropagationData" : [
		ISODate("1601-01-01T00:09:21Z"),
		ISODate("2013-02-13T19:18:07Z")
	],
	"OBJ_col" : 1,
	"recycle_time_col" : NumberLong("3038287259199220266"),
	"objectSid" : "S-1-5-21-1154669122-758131934-2550385761-1153",
	"whenCreated" : ISODate("2013-02-13T19:18:06Z"),
	"uSNCreated" : 110639,
	"mail" : "jean.dupond@labz.net",
	"PDNT_col" : 1796,
	"nTSecurityDescriptor" : 423,
	"sAMAccountName" : "jdupond",
	"objectCategory" : 1369,
	"objectGUID" : "49b5dc8d-9967-4a66-94f6-3caa177ea1e1",
	"Ancestors_col" : [
		2,
		1787,
		1788,
		1789,
		1796,
		8788
	],
	"NCDNT_col" : 1789,
	"time_col" : ISODate("2013-02-13T19:18:06Z"),
	"cnt_col" : 1,
	"whenChanged" : ISODate("2013-02-13T19:19:00Z"),
	"RDNtyp_col" : 3,
	"displayName" : "jean dupond",
	"name" : "jean dupond",
	"userAccountControl" : {
		"flags" : {
			"notDelegated" : false,
			"homedirRequired" : false,
			"useDESKeyOnly" : false,
			"trustedForDelegation" : false,
			"normalAccount" : true,
			"smartcardRequired" : false,
			"mnsLogonAccount" : false,
			"script" : false,
			"dontRequirePreAuth" : false,
			"dontExpirePassword" : false,
			"tempDuplicateAccount" : false,
			"accountDisable" : false,
			"interdomainTrustAccount" : false,
			"passwdCantChange" : false,
			"partialSecretsAccount" : false,
			"trustedToAuthForDelegation" : false,
			"encryptedTextPassAllowed" : false,
			"passwordExpired" : false,
			"lockout" : false,
			"passwdNotrequired" : false,
			"workstationTrustAccount" : false,
			"serverTrustAccount" : false
		},
		"value" : 512
	},
	"sAMAccountType" : 805306368,
	"uSNChanged" : 110650,
	"sn" : "dupond",
	"accountExpires" : ISODate("1970-01-01T01:00:00Z")
    })

    for sd in ["""
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
3lE0""","""
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
dVvSbWlXrOHipjSr/vDHZbl+V2q4u5gveNessOzz07vbq+8uP5br0e2H8t+ZwvP5wvGKt9d30/V+
vC435fL24cPz3g/LRf1QLsLt6Pcyv+iT37tsZ/uO+tvrq7tPKxzd/QF8acqmp1hqZ9iXbuHulN+N
D4Bz3nx8evb1+9FN+//Pf52cplRubr4PN/95dEE+lJAfLtX0+0/fnX8Y/frx9t35u3JRbstP16U8
UXz2cXQxu/vfhz9Hv939dnpxcfXH3HH9sz2Y8bXu3Vq7vz/Efzenqbe428/JscwuMf7g/PPNbfnt
vKS75ks+926gPdjmOnx6uJzTstOznz68n+zA7PX8VNKojtJ4kZvmcGbLPl+mj9dXl6P/zZ6Zb0tz
bM0KzRfN7eD9/p2mi8fno7l+i1uY/7LJaV5carz+7E7dhsscrvPNZI+bu/NudD13BWbO5nUJi5fu
oby9/xc33XcqHtYZ7093hh/t6td/NlfmYWdn72Ru2v8mF/6b+zvz4R69j4LJIj99/lQeovVekJ6y
xyHD23+e+IYfLi8+N9dq9qjvxvdWvevuuqa0XX9mifamDKPmELttzK8/2aveom/C6KLkZZv9x1V7
GsOvzSXqXfv+nMx8PHuoYxnOv3vX/HlyTpw0CU6ca2WM50KQ1Y5L7qUioTWTTlvTLKTlydypbNdW
iRslGCPBEms2kRkFaxwxFgJjpjAtfLvWdPnuiCax30Vzuy+TQNHttYZH8AgewaMXeaSrYIJxRtYH
PfHINx80HiWmahJZpQqP4BE8gke78CgmFpJQY488PIJH8Age7dEjJi1zrjYVtFDaTWRBUTVbaOpr
LHnjqpeor8GjwXvUneHnOVIOHA2DI2570qPqjQ22EsvFdM1Hwumu+Ugy5YsAR+Bo6BwhPRqWR1KQ
NqynudoEHxtmyDT5DymmA0VbHNXqgnZZaZPX8EYpeANvkP6Am5YbvsiNydH4wBP5to7VuMMplJib
9Iax6pg0NnFwA27ADbjZADfaMR2TERRz8qSUcBR0EeS0CayqxJ0u4OZmhowXaPO4ENzssTYlNKpT
WweHU09NKkQreNCSeBG169hy3HctN6od9xPXsIbBGlgDa47eGk0c2AAbYANs9oyNATZotDkObNAn
tRNr+lpsfAyiKtEODxR9wwPlOsMDYQ2sgTWwpt+aolxmXCuKqbpJZ5SzTHTWRG+YZrAG1sAaWPNa
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
cfp1lEtsO2Ps0/8BbRB66w==""","""
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"""]:
        
        db.sd_table.insert(json.loads(sd.decode("base64").decode("zip")))
        
    return db
