# This file is part of the BTA toolset
# (c) Airbus Group CERT, Airbus Group Innovations and Airbus DS CyberSecurity

WellKnownSID = {'ML_PROTECTED_PROCESS': 'S-1-16-20480',
                'PRINTER_OPERATORS': 'S-1-5-32-550',
                'RDS_MANAGEMENT_SERVERS': 'S-1-5-32-577',
                'EVERYONE': 'S-1-1-0',
                'EVENT_LOG_READERS': 'S-1-5-32-573',
                'ENTERPRISE_DOMAIN_CONTROLLERS': 'S-1-5-9',
                'AUTHENTICATED_USERS': 'S-1-5-11',
                'DIALUP': 'S-1-5-1',
                'OTHER_ORGANIZATION': 'S-1-5-1000',
                'ACCESS_CONTROL_ASSISTANCE_OPS': 'S-1-5-32-579',
                'ML_SYSTEM': 'S-1-16-16384',
                'INTERACTIVE': 'S-1-5-4',
                'AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY': 'S-1-18-1',
                'CONSOLE_LOGON': 'S-1-2-1',
                'NT_SERVICE': 'S-1-5-80',
                'WRITE_RESTRICTED_CODE': 'S-1-5-33',
                'ALL_APP_PACKAGES': 'S-1-15-2-1',
                'BUILTIN_GUESTS': 'S-1-5-32-546',
                'ML_MEDIUM': 'S-1-16-8192',
                'PRINCIPAL_SELF': 'S-1-5-10',
                'INCOMING_FOREST_TRUST_BUILDERS': 'S-1-5-32-557',
                'BUILTIN_ADMINISTRATORS': 'S-1-5-32-544',
                'ML_MEDIUM_PLUS': 'S-1-16-8448',
                'USER_MODE_DRIVERS': 'S-1-5-84-0-0-0-0-0',
                'OWNER_SERVER': 'S-1-3-2',
                'COMPOUNDED_AUTHENTICATION': 'S-1-5-21-0-0-0-496',
                'ACCOUNT_OPERATORS': 'S-1-5-32-548',
                'ALIAS_PREW2KCOMPACC': 'S-1-5-32-554',
                'RDS_REMOTE_ACCESS_SERVERS': 'S-1-5-32-575',
                'NETWORK_CONFIGURATION_OPS': 'S-1-5-32-556',
                'CRYPTOGRAPHIC_OPERATORS': 'S-1-5-32-569',
                'SERVER_OPERATORS': 'S-1-5-32-549',
                'BACKUP_OPERATORS': 'S-1-5-32-551',
                'ANONYMOUS': 'S-1-5-7',
                'THIS_ORGANIZATION_CERTIFICATE': 'S-1-5-65-1',
                'SERVICE': 'S-1-5-6',
                'NT_AUTHORITY': 'S-1-5',
                'SERVICE_ASSERTED_IDENTITY': 'S-1-18-2',
                'ML_UNTRUSTED': 'S-1-16-0',
                'REPLICATOR': 'S-1-5-32-552',
                'DISTRIBUTED_COM_USERS': 'S-1-5-32-562',
                'SCHANNEL_AUTHENTICATION': 'S-1-5-64-14',
                'CREATOR_GROUP': 'S-1-3-1',
                'PROXY': 'S-1-5-8',
                'NTLM_AUTHENTICATION': 'S-1-5-64-10',
                'DIGEST_AUTHENTICATION': 'S-1-5-64-21',
                'IIS_IUSRS': 'S-1-5-32-568',
                'CERTIFICATE_SERVICE_DCOM_ACCESS': 'S-1-5-32-574',
                'REMOTE_DESKTOP': 'S-1-5-32-555',
                'CLAIMS_VALID': 'S-1-5-21-0-0-0-497',
                'ML_HIGH': 'S-1-16-12288',
                'TERMINAL_SERVER_LICENSE_SERVERS': 'S-1-5-32-561',
                'POWER_USERS': 'S-1-5-32-547',
                'IUSR': 'S-1-5-17',
                'THIS_ORGANIZATION': 'S-1-5-15',
                'LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP': 'S-1-5-114',
                'NETWORK': 'S-1-5-2',
                'PERFLOG_USERS': 'S-1-5-32-559',
                'OWNER_RIGHTS': 'S-1-3-4',
                'BUILTIN_USERS': 'S-1-5-32-545',
                'WINDOWS_AUTHORIZATION_ACCESS_GROUP': 'S-1-5-32-560',
                'NULL': 'S-1-0-0',
                'REMOTE_MANAGEMENT_USERS': 'S-1-5-32-580',
                'GROUP_SERVER': 'S-1-3-3',
                'HYPER_V_ADMINS': 'S-1-5-32-578',
                'LOCAL_SYSTEM': 'S-1-5-18',
                'LOCAL_ACCOUNT': 'S-1-5-113',
                'RESTRICTED_CODE': 'S-1-5-12',
                'ML_LOW': 'S-1-16-4096',
                'RDS_ENDPOINT_SERVERS': 'S-1-5-32-576',
                'BATCH': 'S-1-5-3',
                'NETWORK_SERVICE': 'S-1-5-20',
                'CREATOR_OWNER': 'S-1-3-0',
                'LOCAL_SERVICE': 'S-1-5-19',
                'LOCAL': 'S-1-2-0',
                'TERMINAL_SERVER_USER': 'S-1-5-13',
                'PERFMON_USERS': 'S-1-5-32-558',
                'REMOTE_INTERACTIVE_LOGON': 'S-1-5-14',
                'CERT_PUBLISHERS': 'S-1-5-21-.*-517',
                'RAS_SERVERS': 'S-1-5-21-.*-553',
                'ENTERPRISE_ADMINS': 'S-1-5-21-.*-519',
                'ENTERPRISE_READONLY_DOMAIN_CONTROLLERS': 'S-1-5-21-.*-498',
                'PROTECTED_USERS': 'S-1-5-21-.*-525',
                'DOMAIN_ADMINS': 'S-1-5-21-.*-512',
                'SCHEMA_ADMINISTRATORS': 'S-1-5-21-.*-518',
                'DOMAIN_COMPUTERS': 'S-1-5-21-.*-515',
                'DOMAIN_USERS': 'S-1-5-21-.*-513',
                'ADMINISTRATOR': 'S-1-5-21-.*-500',
                'GROUP_POLICY_CREATOR_OWNERS': 'S-1-5-21-.*-520',
                'DOMAIN_GUESTS': 'S-1-5-21-.*-514',
                'LOGON_ID': 'S-1-5-5-.*-.*',
                'GUEST': 'S-1-5-21-.*-501',
                'KRBTGT': 'S-1-5-21-.*-502',
                'DOMAIN_DOMAIN_CONTROLLERS': 'S-1-5-21-.*-516',
                'READONLY_DOMAIN_CONTROLLERS': 'S-1-5-21-.*-521',
                'CLONEABLE_CONTROLLERS': 'S-1-5-21-.*-522',}

def SID2String(sid):
    import re
    for k,v in WellKnownSID.items():
        if re.match("^%s$"%v,sid) is not None:
            return k
    return sid

def SID2StringFull(sid, guid_table, only_converted=False):
  # Try to resolve with well known SID
    import re
    sid=sid.lower()
    try:
        for k,v in WellKnownSID.items():
            if re.match("^%s$"%v.lower(),sid) is not None:
                # Do we have a variable part to retreive ?
                variable=""
                if v.count(".*")==1:
                    #print "I will find >%s<"%sid[:-4]
                    variable = "of %s "%guid_table.find_one({"id":sid[:-4]},{"name":1}).get("name")
                if only_converted:
                    return u"%s"%k
                else:
                    return "%s %s(%s)"%(k, variable, sid)
    except Exception:
        return sid

    #Try to resolve in guid table
    obj = guid_table.find_one({"id":sid})
    if obj is not None:
        if only_converted:
            return obj["name"]
        else:
            return "%s (%s)"%(obj["name"], sid)

    # If everything failed just return the sid
    return sid

def Strings2SID(name, guid_table):
    if name in WellKnownSID.keys():
        return [WellKnownSID[name]]
    else:
        results = guid_table.find({"name":name},{"id":1})
        if results is not None:
            return [t["id"] for t in results]
        return [name]
