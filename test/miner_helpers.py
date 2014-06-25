# -*- coding: utf-8 -*-

# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity



import pytest
import mongomock
from mongomock import ObjectId
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


    return db
