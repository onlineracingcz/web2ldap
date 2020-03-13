# -*- coding: utf-8 -*-
"""
ldapoidreg - Simple dictionary registry for LDAP-related OIDs.

This is used in web2ldap to display further information about
LDAP-related OIDs (e.g. in RootDSE)

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

Comprehensive list initially contributed by Norbert Klasen
"""

from web2ldap.log import logger

OID_LIST = (

    # From https://www.iana.org/assignments/ldap-parameters
    (
        "1.2.826.0.1.3344810.2.3",
        u"Matched Values Control",
        u"",
        u"RFC 3876"
    ),
    (
        "1.2.840.113556.1.4.473",
        u"Server Side Sort Request",
        u"",
        u"RFC 2891"
    ),
    (
        "1.2.840.113556.1.4.474",
        u"Server Side Sort Response",
        u"",
        u"RFC 2891"
    ),
    (
        "1.3.6.1.1.7.1",
        u"LCUP Sync Request Control",
        u"",
        u"RFC 3928"
    ),
    (
        "1.3.6.1.1.7.2",
        u"LCUP Sync Update Control",
        u"",
        u"RFC 3928"
    ),
    (
        "1.3.6.1.1.7.3",
        u"LCUP Sync Done Control",
        u"",
        u"RFC 3928"
    ),
    (
        "1.3.6.1.1.8",
        u"Cancel Operation",
        u"",
        u"RFC 3909"
    ),
    (
        "1.3.6.1.1.12",
        u"Assertion Control",
        u"",
        u"RFC 4528"
    ),
    (
        "1.3.6.1.1.13.1",
        u"LDAP Pre-read Control",
        u"",
        u"RFC 4527"
    ),
    (
        "1.3.6.1.1.13.2",
        u"LDAP Post-read Control",
        u"",
        u"RFC 4527"
    ),
    (
        "1.3.6.1.1.14",
        u"Modify-Increment",
        u"",
        u"RFC 4525"
    ),
    (
        "1.3.6.1.4.1.1466.20036",
        u"Notice of disconnection",
        u"",
        u"RFC 4511"
    ),
    (
        "1.3.6.1.4.1.1466.101.119.1",
        u"Dynamic Refresh",
        u"Extended operation for requesting TTL refresh",
        u"RFC 2589"
    ),
    (
        "1.3.6.1.4.1.1466.20037",
        u"Start TLS",
        u"Request to start Transport Layer Security.",
        u"RFC 2830"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.1",
        u"All Operational Attributes",
        u"Provide a simple mechanism which clients may use to request the return of all operational attributes.",
        u"RFC 3673"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.2",
        u"OC AD Lists",
        u"Return of all attributes of an object class",
        u"RFC 4529"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.3",
        u"True/False filters",
        u"absolute True (&) and False (|) filters",
        u"RFC 4526"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.4",
        u"Language Tag Options",
        u"storing attributes with language tag options in the DIT",
        u"RFC 3866"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.5",
        u"Language Range Options",
        u"language range matching of attributes with language tag options stored in the DIT",
        u"RFC 3866"
    ),

    (
        "1.3.6.1.4.1.4203.1.9.1.1",
        u"Sync Request Control",
        u"syncrepl",
        u"RFC 4533"
    ),
    (
        "1.3.6.1.4.1.4203.1.9.1.2",
        u"Sync State Control",
        u"syncrepl",
        u"RFC 4533"
    ),
    (
        "1.3.6.1.4.1.4203.1.9.1.3",
        u"Sync Done Control",
        u"syncrepl",
        u"RFC 4533"
    ),
    (
        "1.3.6.1.4.1.4203.1.9.1.4",
        u"Sync Info Message",
        u"syncrepl",
        u"RFC 4533"
    ),

    (
        "1.3.6.1.4.1.4203.1.10.1",
        u"Subentries",
        u"",
        u"RFC 3672"
    ),
    (
        "1.3.6.1.4.1.4203.1.11.1",
        u"Modify Password",
        u"modification of user passwords",
        u"RFC 3062"
    ),
    (
        "1.3.6.1.4.1.4203.1.11.3",
        u"Who am I?",
        u"",
        u"RFC 4532"
    ),
    (
        "2.16.840.1.113730.3.4.2",
        u"ManageDsaIT",
        u"",
        u"RFC 3296"
    ),
    (
        "2.16.840.1.113730.3.4.15",
        u"Authorization Identity Response Control",
        u"Returned with bind requests to provide LDAP clients with the DN and authentication method used (useful when SASL or certificate mapping is employed).",
        u"RFC 3829"
    ),
    (
        "2.16.840.1.113730.3.4.16",
        u"Authorization Identity Request Control",
        u"Can be provided with bind requests to indicate to the server that an Authentication Response Control is desired with the bind response.",
        u"RFC 3829"
    ),

    (
        "1.2.826.0.1.334810.2.3",
        u"valuesReturnFilter",
        u"",
        u"RFC 3876"),
    (
        "1.2.840.113549.6.0.0",
        u"Signed Operation",
        u"",
        u"RFC 2649"),
    (
        "1.2.840.113549.6.0.1",
        u"Demand Signed Result",
        u"",
        u"RFC 2649"),
    (
        "1.2.840.113549.6.0.2",
        u"Signed Result",
        u"",
        u"RFC 2649"),
    (
        "1.2.840.113556.1.4.319",
        u"Simple Paged Results",
        u"Control for simple paging of search results",
        u"RFC 2696"),

    # MS Active Directory and ADAM

    (
        '1.2.840.113556.1.4.417',
        u'LDAP_SERVER_SHOW_DELETED_OID',
        u'Show deleted control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),


    (
        '1.2.840.113556.1.4.521',
        u'LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID',
        u'Cross-domain move control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.528',
        u'LDAP_SERVER_NOTIFICATION_OID',
        u'Server search notification control (Forbidden)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.529',
        u'LDAP_SERVER_EXTENDED_DN_OID',
        u'Extended DN control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.619',
        u'LDAP_SERVER_LAZY_COMMIT_OID',
        u'Lazy commit control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.801',
        u'LDAP_SERVER_SD_FLAGS_OID',
        u'Security descriptor flags control  (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        "1.2.840.113556.1.4.802",
        u"SD_FLAGS",
        u"Incremental Retrieval of Multi-valued Properties",
        u"draft-kashi-incremental"),

    (
        '1.2.840.113556.1.4.805',
        u'LDAP_SERVER_TREE_DELETE_OID',
        u'Tree delete control  (Stateless)',
        u'draft-armijo-ldap-treedelete'),

    (
        '1.2.840.113556.1.4.841',
        u'LDAP_SERVER_DIRSYNC_OID',
        u'Directory synchronization control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.970',
        u'',
        u'Get stats control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1338',
        u'LDAP_SERVER_VERIFY_NAME_OID',
        u'Verify name control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1339',
        u'LDAP_SERVER_DOMAIN_SCOPE_OID',
        u'Domain scope control (Stateless): instructs the DC not to generate any LDAP continuation references when performing an LDAP operation',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1340',
        u'LDAP_SERVER_SEARCH_OPTIONS_OID',
        u'Search options control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1413',
        u'LDAP_SERVER_PERMISSIVE_MODIFY_OID',
        u'Permissive modify control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1504',
        u'LDAP_SERVER_ASQ_OID',
        u'Attribute scoped query control (Stateless)',
        u'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1781',
        u'LDAP_SERVER_FAST_BIND_OID',
        u'Fast concurrent bind extended operation (Forbidden)',
        u'Platform SDK: DSML Services for Windows'),

    (
        "1.2.840.113556.1.4.1852",
        u"LDAP_SERVER_QUOTA_CONTROL_OID",
        u"The LDAP_SERVER_QUOTA_CONTROL_OID control is used to pass the SID of a security principal, whose quota is being queried, to the server in a LDAP search operation.",
        u'Platform SDK: DSML Services for Windows'),

    (
        "1.2.840.113556.1.4.1907",
        u"LDAP_SERVER_SHUTDOWN_NOTIFY_OID",
        u"",
        u''),

    (
        "1.2.840.113556.1.4.1948",
        u"LDAP_SERVER_RANGE_RETRIEVAL_NOERR_OID",
        u"",
        u""
    ),

    (
        "1.2.840.113556.1.4.1974",
        u"LDAP_SERVER_FORCE_UPDATE_OID",
        u"force update to always generate a new stamp for the attribute or link value and always replicate",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.1341",
        u"LDAP_SERVER_RODC_DCPROMO_OID",
        u"",
        u""
    ),

    (
        "1.2.840.113556.1.4.2026",
        u"LDAP_SERVER_INPUT_DN_OID",
        u"",
        u""
    ),

    (
        "1.2.840.113556.1.4.2064",
        u"LDAP_SERVER_SHOW_RECYCLED_OID",
        u"specify that tombstones, deleted-objects, and recycled-objects should be visible to the operation",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2065",
        u"LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID",
        u"specify that link attributes that refer to deleted-objects are visible to the search operation",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2066",
        u"LDAP_SERVER_POLICY_HINTS_OID",
        u"makes every password set operation to fully honour password policy",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2090",
        u"LDAP_SERVER_DIRSYNC_EX_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2204",
        u"LDAP_SERVER_TREE_DELETE_EX_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2205",
        u"LDAP_SERVER_UPDATE_STATS_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2206",
        u"LDAP_SERVER_SEARCH_HINTS_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2211",
        u"LDAP_SERVER_EXPECTED_ENTRY_COUNT_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2237",
        u"LDAP_CAP_ACTIVE_DIRECTORY_W8_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2239",
        u"LDAP_SERVER_POLICY_HINTS_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2255",
        u"LDAP_SERVER_SET_OWNER_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2256",
        u"LDAP_SERVER_BYPASS_QUOTA_OID",
        u"",
        u"MS Active Directory"
    ),

    (
        "1.3.6.1.4.1.1466.29539.1",
        u"LDAP_CONTROL_ATTR_SIZELIMIT",
        u"",
        u""),
    (
        "1.3.6.1.4.1.1466.29539.2",
        u"LDAP_CONTROL_NO_COPY",
        u"",
        u""),
    (
        "1.3.6.1.4.1.1466.29539.3",
        u"LDAP_CONTROL_PARTIAL_COPY",
        u"",
        u""),
    (
        "1.3.6.1.4.1.1466.29539.5",
        u"LDAP_CONTROL_NO_CHAINING",
        u"",
        u""),
    (
        "1.3.6.1.4.1.1466.29539.7",
        u"LDAP_CONTROL_ALIAS_ON_UPDATE",
        u"",
        u""),
    (
        "1.3.6.1.4.1.1466.29539.10",
        u"LDAP_CONTROL_TRIGGER",
        u"",
        u""),
    (
        "1.3.6.1.4.1.1466.29539.12",
        u"Chained request control",
        u"Control included with iPlanet Directory Server prevents loops.",
        u"iPlanet Directory Server 5.0 Administrator's Guide"),

    # Syntegra X.500 controls
    # see https://www.openldap.org/lists/ietf-ldapext/200010/msg00127.html
    (
        "2.16.840.1.113531.18.2.1",
        u"LDAP_C_SETOPTIONS_OID",
        u"",
        u""),
    (
        "2.16.840.1.113531.18.2.2",
        u"LDAP_C_SETDONTUSECOPY_OID",
        u"",
        u""),
    (
        "2.16.840.1.113531.18.2.3",
        u"LDAP_C_SETLOCALSCOPE_OID",
        u"",
        u""),
    (
        "2.16.840.1.113531.18.2.4",
        u"LDAP_C_SETOPERATTR_OID",
        u"Return operational attributes as well as user attributes",
        u""),
    (
        "2.16.840.1.113531.18.2.5",
        u"LDAP_C_SETSUBENTRIES_OID",
        u"Return only subentries",
        u""),
    (
        "2.16.840.1.113531.18.2.6",
        u"LDAP_C_SETUSEALIAS_OID",
        u"",
        u""),
    (
        "2.16.840.1.113531.18.2.7",
        u"LDAP_C_SETPREFERCHAIN_OID",
        u"",
        u""),
    (
        "2.16.840.1.113531.18.2.8",
        u"LDAP_C_SETX500DN_OID",
        u"",
        u""),
    (
        "2.16.840.1.113531.18.2.9",
        u"LDAP_C_SETCOPYSHALLDO_OID",
        u"",
        u""),
    (
        "2.16.840.1.113531.18.2.10",
        u"LDAP_C_SETDONTMAPATTRS_OID",
        u"",
        u""),
    (
        "2.16.840.1.113531.18.2.11",
        u"LDAP_C_SETALLENTRIES_OID",
        u"Return normal entries as well as sub-entries",
        u""),

    (
        "2.16.840.1.113719.1.27.101.1",
        u"Duplicate Entry Request",
        u"",
        u"draft-ietf-ldapext-ldapv3-dupent"),
    (
        "2.16.840.1.113719.1.27.101.2",
        u"DuplicateSearchResult",
        u"",
        u"draft-ietf-ldapext-ldapv3-dupent"),
    (
        "2.16.840.1.113719.1.27.101.3",
        u"DuplicateEntryResponseDone",
        u"",
        u"draft-ietf-ldapext-ldapv3-dupent"),
    (
        "2.16.840.1.113719.1.27.101.5",
        u"Simple Password",
        u"not yet documented",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.101.6",
        u"Forward Reference",
        u"not yet documented",
        u"NDS"),

    (
        "2.16.840.1.113719.1.27.101.40",
        u"LDAP_CONTROL_SSTATREQUEST control",
        u"not yet documented",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.101.41",
        u"",
        u"not yet documented",
        u"NDS"),
    (
        "2.16.840.1.113719.1.14.100.91",
        u"GetNamedPasswordRequest",
        u"not yet documented",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.101.57",
        u"VLV result count control",
        u"not yet documented",
        u"NDS"),

    (
        "2.16.840.1.113730.3.4.3",
        u"Persistent Search",
        u"",
        u"draft-ietf-ldapext-psearch"),
    (
        "2.16.840.1.113730.3.4.4",
        u"Password Change After Reset",
        u"an octet string to indicate the user should change his password",
        u"draft-vchu-ldap-pwd-policy"),
    (
        "2.16.840.1.113730.3.4.5",
        u"Password Expiration Warning",
        u"an octet string to indicate the time in seconds until the password expires",
        u"draft-vchu-ldap-pwd-policy"),
    (
        "2.16.840.1.113730.3.4.6",
        u"Netscape NT Synchronization Client",
        u"",
        u""),
    (
        "2.16.840.1.113730.3.4.7",
        u"Entry Change Request",
        u"This control provides additional information about the change the caused a particular entry to be returned as the result of a persistent search.",
        u"draft-ietf-ldapext-psearch"),
    (
        "2.16.840.1.113730.3.4.9",
        u"Virtual List View Request",
        u"",
        u"draft-ietf-ldapext-ldapv3-vlv"),
    (
        "2.16.840.1.113730.3.4.10",
        u"Virtual List View Response",
        u"",
        u"draft-ietf-ldapext-ldapv3-vlv"),
    (
        "2.16.840.1.113730.3.4.11",
        u"Transaction ID Response",
        u"",
        u"http://docs.iplanet.com/docs/manuals/directory.html"),
    (
        "2.16.840.1.113730.3.4.12",
        u"Proxied Authorization",
        u"allows LDAP clients to use different credentials, without rebinding, when executing LDAP operations.",
        u"draft-weltman-ldapv3-proxy"),
    (
        "2.16.840.1.113730.3.4.13",
        u"iPlanet Directory Server Replication Update Information",
        u"",
        u" http://docs.iplanet.com/docs/manuals/directory.html"),
    (
        "2.16.840.1.113730.3.4.14",
        u"Specific Backend Search Request",
        u"iPlanet Directory Server search on specific backend",
        u"http://docs.iplanet.com/docs/manuals/directory.html"),
    (
        "2.16.840.1.113730.3.4.17",
        u"Real Attributes Only",
        u"This control requests that the server only return attributes which are truly contained in the entries returned and that no resolution of virtual attributes be performed (such as defined by class of service and roles).",
        u"http://docs.iplanet.com/docs/manuals/directory.html"),
    (
        "2.16.840.1.113730.3.4.18",
        u"Proxied Authorization",
        u"For assuming the identity of another entry for the duration of a request.",
        u"RFC 4370"),

    (
        "2.16.840.1.113730.3.4.20",
        u"Search on one backend",
        u"",
        u""),


    # Various extensions defined in Internet drafts
    (
        "1.2.826.0.1.3344810.2.0",
        u"Families of Entries",
        u"",
        u"draft-ietf-ldapext-families"
    ),

    #LDAP Server Profiles
    #attribute: ogSupportedProfile
    #http://www.opengroup.org/orc/DOCS/LDAP_PR/text/apdxa.htm
    (
        "1.2.826.0.1050.11.1.1",
        u"Read-Only LDAP Server",
        u"",
        u"Open Group LDAP Server Profiles"),
    (
        "1.2.826.0.1050.11.2.1",
        u"Read-Write LDAP Server",
        u"",
        u"Open Group LDAP Server Profiles"),
    (
        "1.2.826.0.1050.11.3.1",
        u"White Pages Application LDAP Server",
        u"",
        u"Open Group LDAP Server Profiles"),
    (
        "1.2.826.0.1050.11.4.1",
        u"Certificate Application LDAP Server",
        u"",
        u"Open Group LDAP Server Profiles"),
    (
        "1.2.826.0.1050.11.5.1",
        u"Single Sign On Application LDAP Server",
        u"",
        u"Open Group LDAP Server Profiles"),

    (
        "2.16.840.1.113719.1.27.100.36",
        u"setReplicationFilterResponse",
        u"Set Replication Filter Response",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.38",
        u"getReplicationFilterResponse",
        u"Get Replication Filter Response",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.40",
        u"createOrphanNamingContextResponse",
        u"Create Orphan Partition Response",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.42",
        u"removeOrphanNamingContextResponse",
        u"Remove Orphan Partition Response",
        u"NDS"),

    (
        "2.16.840.1.113719.1.27.100.44",
        u"Trigger Backlinker Response",
        u"",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.48",
        u"Trigger Janitor Response",
        u"",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.50",
        u"Trigger Limber Response",
        u"",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.52",
        u"Trigger Skulker Response",
        u"",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.54",
        u"Trigger Schema Synch Response",
        u"",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.56",
        u"Trigger Partition Purge Response",
        u"",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.80",
        u"Monitor Events Response",
        u"",
        u"NDS"),
    (
        "2.16.840.1.113719.1.27.100.81",
        u"Event Notification",
        u"",
        u"NDS"),

    (
        "2.16.840.1.113719.1.27.99.1",
        u"Superior References",
        u"",
        u"Novell eDirectory 8.7+"),

    # DirXML-related OIDs, see http://developer.novell.com/documentation/dirxml/dirxmlbk/api/index.html

    (
        "2.16.840.1.113719.1.14.100.1",
        u"GetDriverSetRequest",
        u"Get the DN of the DirXML-DriverSet object associated with the server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.2",
        u"GetDriverSetResponse",
        u"The response for the GetDriverSetRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.3",
        u"SetDriverSetRequest",
        u"Set the DirXML-DriverSet object associated with a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.5",
        u"ClearDriverSetRequest",
        u"LDAP extension used to disassociate any DirXML driver set associated with a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.7",
        u"GetDriverStartOptionRequest",
        u"Get the start option value of a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.8",
        u"GetDriverStartOptionResponse",
        u"The response for the GetDriverStartOptionRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.9",
        u"SetDriverStartOptionRequest",
        u"Set the start option value of a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.11",
        u"GetVersionRequest",
        u"Get the version number of the DirXML engine associated with the server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.12",
        u"GetVersionResponse",
        u"The response for the GetVersionRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.13",
        u"GetDriverStateRequest",
        u"Get the current state of a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.14",
        u"GetDriverStateResponse",
        u"The response for the GetDriverStateRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.15",
        u"StartDriverRequest",
        u"Start a DirXML driver.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.17",
        u"StopDriverRequest",
        u"Stop a DirXML driver.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.19",
        u"GetDriverStatsRequest",
        u"Get an XML document describing the current state of a DirXML driver on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.20",
        u"GetDriverStatsResponse",
        u"The response for the GetDriverStatsRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.21",
        u"DriverGetSchemaRequest",
        u"Cause a DirXML driver to obtain its application's schema and store the schema in the DirXML-ApplicationSchema attribute on the DirXML-Driver object.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.23",
        u"DriverResyncRequest",
        u"Initiate a resync for a DirXML driver on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.25",
        u"MigrateAppRequest",
        u"Start a migrate from application for a DirXML driver on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.27",
        u"QueueEventRequest",
        u"Queue an event document for a DirXML driver on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.29",
        u"SubmitCommandRequest",
        u"Submit a command document to a DirXML driver on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.30",
        u"SubmitCommandResponse",
        u"The response for the SubmitCommandRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.31",
        u"SubmitEventRequest",
        u"Submit an event document to a DirXML driver on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.32",
        u"SubmitEventResponse",
        u"The response for the SubmitEventRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.33",
        u"GetChunkedResultRequest",
        u"Get part of a large result that is created in response to another data request.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.34",
        u"GetChunkedResultResponse",
        u"The response for the GetChunkedResultRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.35",
        u"CloseChunkedResultRequest",
        u"Clean up any resources associated with a large result that is created in response to another data request.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.37",
        u"CheckObjectPasswordRequest",
        u"LDAP request to check the nspmDistributionPassword value of an eDirectory object against the object's associated password in a connected system.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.38",
        u"CheckObjectPasswordResponse",
        u"The response for the CheckObjectPasswordRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.39",
        u"InitDriverObjectRequest",
        u"Instruct the DirXML Engine to initialize a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.41",
        u"DeleteCacheEntriesRequest",
        u"Delete event records from the cache of a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.45",
        u"GetPasswordsStateRequest",
        u"Get the state of passwords associated with a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.46",
        u"GetPasswordsStateResponse",
        u"The response for the GetPasswordsStateRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.47",
        u"RegenerateKeyRequest",
        u"Cause the DirXML Engine to regenerate the public key/private key pair used for encrypting data when setting passwords.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.49",
        u"GetServerCertRequest",
        u"Get the DirXML server's public key certificate that is used for encrypting data when setting passwords.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.50",
        u"GetServerCertResponse",
        u"The response for the GetServerCertRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.51",
        u"DiscoverJobsRequest",
        u"Discover available job definitions on a DirXML server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.52",
        u"DiscoverJobsResponse",
        u"The response for the DiscoverJobsRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.53",
        u"NotifyJobUpdateRequest",
        u"Notify the DirXML Engine that the data associated with a DirXML-Job object has changed.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.55",
        u"StartJobRequest",
        u"Cause the the DirXML Engine to start a job.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.57",
        u"AbortJobRequest",
        u"LDAP request to cause the the DirXML Engine to abort a running job.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.59",
        u"GetJobStateRequest",
        u"Get the state of a DirXML job.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.60",
        u"GetJobStateResponse",
        u"The response for the GetJobStateRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.61",
        u"CheckJobConfigRequest",
        u"LDAP request to get a report on the configuration of a DirXML job.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.62",
        u"CheckJobConfigResponse",
        u"The response for the CheckJobConfigRequest request.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.63",
        u"SetLogEventsRequest",
        u"Set the filter for reporting events in the DirXML Engine to the logging service.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.65",
        u"ClearLogEventsRequest",
        u"LDAP extension used to clear the event reporting filter used by the DirXML Engine to determine which events to report to the logging service.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.67",
        u"SetAppPasswordRequest",
        u"Set the application password for a DirXML-Driver object associated with a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.69",
        u"ClearAppPasswordRequest",
        u"LDAP extension used to clear the application password for a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.71",
        u"SetRemoteLoaderPasswordRequest",
        u"Set the remote loader password for a DirXML-Driver object associated with a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.73",
        u"ClearRemoteLoaderPasswordRequest",
        u"LDAP extension used to clear the Remote Loader password for a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.75",
        u"SetNamedPasswordRequest",
        u"Set a named password for an eDirectory object associated with a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.77",
        u"RemoveNamedPasswordRequest",
        u"Remove a named password from an eDirectory object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.79",
        u"RemoveAllNamedPasswordsRequest",
        u"Remove all named passwords from an eDirectory object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.81",
        u"ListNamedPasswordsRequest",
        u"List any named passwords from an eDirectory object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.82",
        u"ListNamedPasswordsResponse",
        u"The response for the ListNamedPasswordsRequest operation.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.41",
        u"ViewCacheEntriesRequest",
        u"View event records in the cache of a DirXML-Driver object on a server.",
        u"Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.42",
        u"ViewCacheEntriesResponse",
        u"The response for the ViewCacheEntriesRequest operation.",
        u"Novell DirXML",
    ),



    (
        "1.3.6.1.4.1.4203.1.10.2",
        u"No-Op Control",
        u"",
        u"draft-zeilenga-ldap-noop"),
    (
        "1.3.6.1.4.1.4203.1.11.2",
        u"LDAP Cancel Extended Operation",
        u"",
        u"RFC 3909"),

    # See https://www.openldap.org/faq/data/cache/212.html
    (
        "1.3.6.1.4.1.4203.666.5.1",
        u"Subentries Control",
        u"not valid anymore",
        u"draft-zeilenga-ldap-subentry"),
    (
        "1.3.6.1.4.1.4203.666.5.2",
        u"No-Op Control",
        u"experimental OID - not valid anymore",
        u"draft-zeilenga-ldap-noop"),

    # OpenLDAP's ldap.h - various works in progress
    (
        "1.3.6.1.4.1.4203.666.5.9",
        u"LDAP_CONTROL_ASSERT",
        u"",
        u"OpenLDAP's ldap.h: various works in progress"),
    (
        "1.3.6.1.4.1.4203.666.5.10.1",
        u"LDAP_CONTROL_PRE_READ",
        u"",
        u"OpenLDAP's ldap.h: various works in progress"),
    (
        "1.3.6.1.4.1.4203.666.5.10.2",
        u"LDAP_CONTROL_POST_READ",
        u"",
        u"OpenLDAP's ldap.h: various works in progress"),
    (
        "1.3.6.1.4.1.4203.666.11.3",
        u"Chaining Behavior",
        u"",
        u"draft-sermersheim-ldap-chaining"),
    (
        "1.3.6.1.4.1.4203.666.5.11",
        u"LDAP_CONTROL_NO_SUBORDINATES",
        u"",
        u"OpenLDAP's ldap.h: various works in progress"),
    (
        "1.3.6.1.4.1.4203.666.5.12",
        u"Relax Rules Control",
        u"",
        u"draft-zeilenga-ldap-relax, see also OpenLDAP's ldap.h"),
    (
        "1.3.6.1.4.1.4203.666.5.14",
        u"Values Sort Control",
        u"",
        u"OpenLDAP's ldap.h: OpenLDAP Experimental Features"),
    (
        "1.3.6.1.4.1.4203.666.5.15",
        u"Don't Use Copy Control",
        u"",
        u"OpenLDAP's ldap.h: OpenLDAP Experimental Features"),
    (
        "1.3.6.1.1.22",
        u"Don't Use Copy Control",
        u"The requested operation MUST NOT be performed on copied information.",
        u"RFC 6171"),

    (
        "1.3.6.1.4.1.4203.666.5.17",
        u"What Failed? Control",
        u"",
        u"draft-masarati-ldap-whatfailed"),
    # see https://bugs.openldap.org/show_bug.cgi?id=6598
    (
        "1.3.6.1.4.1.4203.666.5.18",
        u"No-Op Search Control",
        u"",
        u"OpenLDAP ITS#6598"),

    # OpenLDAP's ldap.h: LDAP Experimental (works in progress) Features
    (
        "1.3.6.1.4.1.4203.666.8.2",
        u"LDAP_FEATURE_MODIFY_INCREMENT",
        u"",
        u"OpenLDAP's ldap.h: OpenLDAP Experimental Features"),
    (
        "1.3.6.1.4.1.4203.666.8.1",
        u"LDAP_FEATURE_SUBORDINATE_SCOPE",
        u"",
        u"OpenLDAP's ldap.h: OpenLDAP Experimental Features"),

    # LDAP Transactions (draft-zeilenga-ldap-txn)
    # See https://www.openldap.org/faq/data/cache/1330.html
    (
        "1.3.6.1.4.1.4203.666.11.7.1",
        u"",
        u"LDAP Transactions Extended Operation",
        u"OpenLDAP's ldap.h: OpenLDAP Experimental Features (draft-zeilenga-ldap-txn)"),
    (
        "1.3.6.1.4.1.4203.666.11.7.2",
        u"",
        u"LDAP Transactions Extended Control",
        u"OpenLDAP's ldap.h: OpenLDAP Experimental Features (draft-zeilenga-ldap-txn)"),
    (
        "1.3.6.1.4.1.4203.666.11.7.3",
        u"",
        u"LDAP Transactions Extended Operation",
        u"OpenLDAP's ldap.h: OpenLDAP Experimental Features (draft-zeilenga-ldap-txn)"),

    # See https://www.openldap.org/faq/data/cache/1280.html
    (
        "1.3.6.1.4.1.4203.666.11.6.1",
        u"chainedRequest",
        u"",
        u"draft-sermersheim-ldap-distproc"),
    (
        "1.3.6.1.4.1.4203.666.11.6.2",
        u"canChainOperations",
        u"",
        u"draft-sermersheim-ldap-distproc"),
    (
        "1.3.6.1.4.1.4203.666.11.6.3",
        u"returnContinuationReference",
        u"",
        u"draft-sermersheim-ldap-distproc"),

    (
        "1.3.6.1.4.1.4203.666.11.9.5.1",
        u"Proxy cache privateDB control",
        u"Allows regular LDAP operations with respect to the private database instead of the proxied one.",
        u"OpenLDAP Experimental Features"),
    (
        "1.3.6.1.4.1.4203.666.11.9.6.1",
        u"Proxy cache queryDelete ext.op.",
        u"",
        u"OpenLDAP Experimental Features"),
    (
        "1.3.6.1.4.1.4203.666.5.16",
        u"LDAP Dereference Control",
        u"This control is intended to collect extra information related to cross-links present in entries returned as part of search responses.",
        u"draft-masarati-ldap-deref"),

    (
        "1.3.6.1.4.1.4203.666.6.5",
        u"LDAP Verify Credentials operation",
        u"",
        u"OpenLDAP Experimental Features"),

    # draft-behera-ldap-password-policy
    (
        "1.3.6.1.4.1.42.2.27.8.5.1",
        u"passwordPolicyRequest",
        u"A control to request for requesting / receiving information about password policy",
        u"draft-behera-ldap-password-policy"),

    (
        "2.16.840.1.113730.3.5.3",
        u"iPlanet Start Replication Request Extended Operation",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.4",
        u"iPlanet Replication Response Extended Operation",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.5",
        u"iPlanet End Replication Request Extended Operation",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.6",
        u"iPlanet Replication Entry Request Extended Operation",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.7",
        u"iPlanet Bulk Import Start Extended Operation",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.8",
        u"iPlanet Bulk Import Finished Extended Operation",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.9",
        u"iPlanet Digest Authentication Calculation Extended Operation",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.10",
        u"iPlanet Distributed Numeric Assignment Request",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.11",
        u"iPlanet Distributed Numeric Assignment Response",
        u"",
        u"iPlanet Directory 5.0+"),

    (
        "2.16.840.1.113730.3.4.19",
        u"iPlanet Virtual Attributes Only",
        u"",
        u"iPlanet Directory 5.0+"),

    (
        "1.3.6.1.4.1.42.2.27.9.5.2",
        u"Get Effective Rights",
        u"",
        u"iPlanet Directory 5.0+"),
    (
        "1.3.6.1.4.1.42.2.27.9.5.8",
        u"Account Usability Control",
        u"Determine whether a user account may be used for authenticating to the server.",
        u"iPlanet Directory 5.0+"),

    # supportedCapabilities
    # http://msdn.microsoft.com/en-us/library/cc223359(PROT.13).aspx
    (
        "1.2.840.113556.1.4.800",
        u"LDAP_CAP_ACTIVE_DIRECTORY_OID",
        u"This LDAP server is an Active Directory server (Windows 2000 and later).",
        u"Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1670",
        u"LDAP_CAP_ACTIVE_DIRECTORY_V51_OID",
        u"This LDAP server is a 'Whistler' Active Directory server (Windows 2003 and later).",
        u"Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1791",
        u"LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID",
        u"This LDAP server is supports signing and sealing on an NTLM authenticated connection, and is capable of performing subsequent binds on such a connection.",
        u"Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1935",
        u"LDAP_CAP_ACTIVE_DIRECTORY_V60_OID",
        u"Windows Server 2008 AD DS and Windows Server 2008 AD LDS",
        u"Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1880",
        u"LDAP_CAP_ACTIVE_DIRECTORY_ADAM_DIGEST",
        u"DC accepts DIGEST-MD5 binds for AD LDSsecurity principals",
        u"Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1851",
        u"LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID",
        u"",
        u"Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1920",
        u"LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID",
        u"indicates that the DC is an RODC",
        u"Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.2080",
        u"LDAP_CAP_ACTIVE_DIRECTORY_V61_R2_OID",
        u"Windows Server 2008R2 AD DS and Windows Server 2008R2 AD LDS",
        u"Microsoft Active Directory"),

    # draft-ietf-ldup-subentry-07.txt
    (
        "1.3.6.1.4.1.7628.5.101.1",
        u"ldapSubentriesControl",
        u"",
        u"draft-ietf-ldup-subentry"),

    # SunONE Directory Server 5.2+
    (
        "1.3.6.1.4.1.42.2.27.9.6.1",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.2",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.3",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.4",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.5",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.6",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.7",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.8",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.9",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.11",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.12",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.13",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.14",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.15",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.16",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.17",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.18",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.19",
        u"",
        u"Replication Protocol related.",
        u"SunONE Directory Server 5.2+"),

    (
        "1.3.6.1.4.1.42.2.27.9.6.21",
        u"",
        u"???",
        u"SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.22",
        u"",
        u"???",
        u"SunONE Directory Server 5.2+"),

    ############################################################################
    # IBM Directory Server
    # see http://www-01.ibm.com/support/knowledgecenter/api/content/nl/en/SSVJJU_6.3.1/com.ibm.IBMDS.doc_6.3.1/admin_gd517.htm
    ############################################################################

    # ACI mechanisms

    (
        "1.3.18.0.2.26.2",
        u"IBM SecureWay V3.2 ACL Model",
        u"Indicates that the LDAP server supports the IBM SecureWay V3.2 ACL model",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.26.3",
        u"IBM Filter Based ACL Mechanism",
        u"Indicates that the LDAP server supports IBM Directory Server v5.1 filter based ACLs.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.26.4",
        u"System Restricted ACL Support",
        u"Server supports specification and evaluation of ACLs on system and restricted attributes.",
        u"IBM Directory Server"),

    # Extended operations

    (
        "1.3.18.0.2.12.58",
        u"Account status extended operation",
        u"This extended operation sends the server a DN of an entry which contains a userPassword attribute, and the server sends back the status of the user account being queried:open, locked or expired",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.46",
        u"Attribute type extended operations",
        u"Retrieve attributes by supported capability: operational, language tag, attribute cache, unique or configuration.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.5",
        u"Begin transaction extended operation",
        u"Begin a Transactional context.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.15",
        u"Cascading replication operation extended operation",
        u"This operation performs the requested action on the server it is issued to and cascades the call to all consumers beneath it in the replication topology.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.20",
        u"Clear log extended operation",
        u"Request to Clear log file.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.16",
        u"Control replication extended operation",
        u"This operation is used to force immediate replication, suspend replication, or resume replication by a supplier. This operation is allowed only when the client has update authority to the replication agreement",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.17",
        u"Control queue extended operation",
        u'This operation marks items as "already replicated" for a specified agreement. This operation is allowed only when the client has update authority to the replication agreement.',
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.30",
        u"DN normalization extended operation",
        u"Request to normalize a DN or a sequence of DNs.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.40",
        u"Dynamic server trace extended operation",
        u"Activate or deactivate tracing in the IBM Tivoli Directory Server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.28",
        u"Update configuration extended operation",
        u"Request to update server configuration for IBM Tivoli Directory Server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.6",
        u"End transaction extended operation",
        u"End Transactional context (commit/rollback),.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.1",
        u"Event notification register request extended operation",
        u"Request registration for events notification.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.3",
        u"Event notification unregister request extended operation",
        u"Unregister for events that were registered for using an Event Registration Request.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.22",
        u"Get lines extended operation",
        u"Request to get lines from a log file.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.24",
        u"Get number of lines extended operation",
        u"Request number of lines in a log file.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.50",
        u"Group evaluation extended operation",
        u"Requests all the groups that a given user belongs to.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.35",
        u"Kill connection extended operation",
        u"Request to kill connections on the server. The request can be to kill all connections or kill connections by bound DN, IP, or a bound DN from a particular IP.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.41",
        u"LDAP trace facility extended operation",
        u"Use this extended operation to control LDAP Trace Facility remotely using the Admin Daemon.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.19",
        u"Quiesce or unquiesce replication context extended operation",
        u"This operation puts the subtree into a state where it does not accept client updates (or terminates this state),, except for updates from clients authenticated as directory administrators where the Server Administration control is present.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.56",
        u"Replication error log extended operation",
        u"Maintenance of a replication error table.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.54",
        u"Replication topology extended operation",
        u"Trigger a replication of replication topology-related entries under a given replication context.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.26",
        u"Start, stop server extended operations",
        u"Request to start, stop or restart an LDAP server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.44",
        u"Unique attributes extended operation",
        u"Feature to enforce attribute uniqueness.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.31",
        u"Update event notification extended operation",
        u"Request that the event notification plug-in get the updated configuration from the server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.32",
        u"Update log access extended operation",
        u"Request that the log access plug-in get the updated configuration from the server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.37",
        u"User type extended operation",
        u"Request to get the User Type of the bound user.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.64",
        u"Prepare transaction extended operation",
        u"Requests the server to start processing the operations sent in a transaction.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.74",
        u"Online backup extended operation",
        u"Perform online backup of the directory server instance's database.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.75",
        u"Effective password policy extended operation",
        u"Query effective password policy for a user or a group.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.79",
        u"Password policy bind initialize and verify extended operation",
        u"Performs password policy bind initialization and verification for a specified user.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.80",
        u"Password policy finalize and verify bind extended operation",
        u"Performs password policy post-bind processing for a specified user.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.73",
        u"Get file extended operation",
        u"Return the contents of a given file on the server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.12.70",
        u"LogMgmtControl extended operation",
        u"Start, stop, or query the status of the log management.",
        u"IBM Directory Server"),

    # Extended controls

    (
        "1.3.18.0.2.10.28",
        u"AES bind control",
        u"This control enables the IBM Tivoli Directory Server to send updates to the consumer server with passwords already encrypted using AES.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.22",
        u"Audit control",
        u"The control sends a sequence of uniqueid strings and a source ip string to the server. When the server receives the control, it audits the list of uniqueids and sourceip in the audit record of the operation.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.23",
        u"Do not replicate control",
        u"This control can be specified on an update operation (add, delete, modify,modDn, modRdn).",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.21",
        u"Group authorization control",
        u"The control sends a list of groups that a user belongs to.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.25",
        u"Modify groups only control",
        u"Attached to a delete or modify DN request to cause the server to do only the group referential integrity processing for the delete or rename request without doing the actual delete or rename of the entry itself. The entry named in the delete or modify DN request does not need to exist on the server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.27",
        u"No replication conflict resolution control",
        u"When present, a replica server accepts a replicated entry without trying to resolve any replication conflict for this entry.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.26",
        u"Omit group referential integrity control",
        u"Omits the group referential integrity processing on a delete or modrdn request.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.24",
        u"Refresh entry control",
        u"This control is returned when a target server detects a conflict (T0!=T2 & T1>T2) during a replicated modify operation.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.18",
        u"Replication supplier bind control",
        u"This control is added by the supplier, if the supplier is a gateway server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.29",
        u"Replication update ID control",
        u"This control was created for serviceability. If the supplier server is set to issue the control, each replicated update is accompanied by this control.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.15",
        u"Server administration control",
        u"Allows an update operation by the administrator under conditions when the operation would normally be refused (server is quiesced, a read-only replica, etc.)",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.5",
        u"Transaction control",
        u"Marks the operation as part of a transactional context.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.30",
        u"Limit number of attribute values control",
        u"Limit the number of attribute values returned for an entry in a search operation.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.32",
        u"Delete operation timestamp control",
        u"Send the modified timestamp values to a replica during a delete operation.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.10.33",
        u"Return deleted objects control",
        u"Return all entries in the database including those with (isDeleted=TRUE).",
        u"IBM Directory Server"),

    # Supported and enabled capabilities

    (
        "1.3.18.0.2.32.1",
        u"Enhanced Replication Model",
        u"Identifies the replication model introduced in IBM Directory Server v5.1 including subtree and cascading replication.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.2",
        u"Entry Checksum",
        u"Indicates that this server supports the ibm-entrychecksum and ibm-entrychecksumop features.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.3",
        u"Entry UUID",
        u"This value is listed in the ibm-capabilities Subentry for those suffixes that support the ibm-entryuuid attribute.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.4",
        u"Filter ACLs",
        u"Identifies that this server supports the IBM Filter ACL model",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.5",
        u"Password Policy",
        u"Identifies that this server supports password policies",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.6",
        u"Sort by DN",
        u"Enables searches sorted by DNs in addition to regular attributes.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.8",
        u"Administration Group Delegation",
        u"Server supports the delegation of server administration to a group of administrators that are specified in the configuration backend.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.9",
        u"Denial of Service Prevention",
        u"Server supports the denial of service prevention feature, including read/write time-outs and the emergency thread.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.10",
        u"Dereference Alias Option",
        u"Server supports an option to not dereference aliases by default",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.11",
        u"Admin Daemon Audit Logging",
        u"Server supports the auditing of the admin daemon.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.12",
        u"128 Character Table Names",
        u"The server feature to allow name of unique attributes to be higher than 18 characters (with the maximum of 128 characters).",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.13",
        u"Attribute Caching Search Filter Resolution",
        u"The server supports attribute caching for search filter resolution.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.14",
        u"Dynamic Tracing",
        u"Server supports active tracing for the server with an LDAP extended operation.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.15",
        u"Entry And Subtree Dynamic Updates",
        u"The server supports dynamic configuration updates on entries and subtrees.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.16",
        u"Globally Unique Attributes",
        u"The server feature to enforce globally unique attribute values.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.17",
        u"Group-Specific Search Limits",
        u"Supports extended search limits for a group of people.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.18",
        u"IBMpolicies Replication Subtree",
        u"Server supports the replication of the cn=IBMpolicies subtree.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.19",
        u"Max Age ChangeLog Entries",
        u"Specifies that the server is capable of retaining changelog entries based on age.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.20",
        u"Monitor Logging Counts",
        u"The server provides monitor logging counts for messages added to server, command-line interface, and audit log files.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.21",
        u"Monitor Active Workers Information",
        u"The server provides monitor information for active workers (cn=workers,cn=monitor).",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.22",
        u"Monitor Connection Type Counts",
        u"The server provides monitor connection type counts for SSL and TLS connections.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.23",
        u"Monitor Connections Information",
        u"The server provides monitor information for connections by IP address instead of connection ID (cn=connections, cn=monitor)",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.24",
        u"Monitor Operation Counts",
        u"The server provides new monitor operation counts for initiated and completed operation types.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.25",
        u"Monitor Tracing Info",
        u"The server provides monitor information for tracing options currently being used.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.26",
        u"Null Base Subtree Search",
        u"Server allows null based subtree search, which searches the entire DIT defined in the server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.27",
        u"Proxy Authorization",
        u"Server supports Proxy Authorization for a group of users.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.28",
        u"TLS Capabilities",
        u"Specifies that the server is actually capable of doing TLS.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.29",
        u"Non-Blocking Replication",
        u"The server is capable of ignoring some errors received from a consumer (replica) that would normally cause an update to be re-transmitted periodically until a successful result code was received.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.30",
        u"Kerberos Capability",
        u"Specifies that the server is capable of using Kerberos.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.31",
        u"ibm-allMembers and ibm-allGroups operational attributes",
        u"Indicates whether or not a backend supports searching on the ibm-allGroups and ibm-allMembers operational attributes.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.32",
        u"FIPS mode for GSKit",
        u"Enables the server to use the encryption algorithms from the ICC FIPS-certified library",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.35",
        u"Modify DN (leaf move)",
        u"Indicates if modify DN operation supports new superior for leaf entries. Note that this capability is implied by the pre-existing Modify DN (subtree move) capability. Applications should check for both capabilities.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.36",
        u"Filtered Referrals",
        u"The server supports limited filtered referrals.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.37",
        u"Simplify resizing of attributes",
        u"Allows customers to increase the maximum length of attributes through the schema modification facilities.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.38",
        u"Global Administration Group",
        u"Server supports the delegation of server administration to a group of administrators that are specified in the RDBM backend. Global Administrators do not have any authority to the configuration file or log files.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.39",
        u"AES Encryption Option",
        u"Server supports auditing of compare operations.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.40",
        u"Auditing of Compare",
        u"Server supports auditing of compare operations.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.41",
        u"Log Management",
        u"Identifies that this server supports log management.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.42",
        u"Multi-threaded Replication",
        u"Replication agreements can specify using multiple threads and connections to a consumer.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.43",
        u"Supplier Replication Configuration",
        u"Server configuration of suppliers for replication.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.44",
        u"Using CN=IBMPOLICIES for Global Updates",
        u"Server supports the replication of global updates using the replication topology in cn=IBMpolicies subtree.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.45",
        u"Multihomed configuration support",
        u"Server supports configuration on multiple IP addresses (multihomed).",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.46",
        u"Multiple Directory Server Instances Architecture",
        u"Server is designed to run with multiple directory server instances on the same machine.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.47",
        u"Configuration Tool Auditing",
        u"Server supports the auditing of the the configuration tools.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.48",
        u"Audit consolidation configuration settings",
        u"Indicates that audit log settings are available in the configuration file.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.49",
        u"Proxy Server",
        u"Describes whether this server is capable of acting as a proxy server or regular RDBM server. Optional Information.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.50",
        u"LDAP Attribute Cache Auto Adjust",
        u"Indicates if autonomic attribute cache is supported and enabled (deprecated in 6.3+).",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.51",
        u"Replication conflict resolution max entry size",
        u"Based on this number, a supplier may decide if an entry should be re-added to a target server in order to resolve a replication conflict.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.52",
        u"LostAndFound log file",
        u"Supports LostAndFound file for archiving replaced entries as a result of replication conflict resolution.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.53",
        u"Password Policy Account Lockout",
        u"Identifies that this server supports password policy Account Locked feature.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.54",
        u"Password Policy Admin",
        u"Identifies that this server supports Admin Password Policy.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.55",
        u"IDS 6.0 SSL Fips processing mode",
        u"Server supports SSL FIPS mode processing.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.56",
        u"IDS 6.0 ibm-entrychecksumop",
        u"Identifies that the 6.0 version of the ibm-entrychecksumop calculation was used on the server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.57",
        u"LDAP Password Global Start Time",
        u"Indicates that the server can support ibm-pwdPolicyStartTime attribute in the cn=pwdPolicy entry.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.58",
        u"Audit Configuration Settings Consolidation",
        u"Identifies that the audit configuration settings are now residing in the ibmslapd configuration file only.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.59",
        u"CBE Log Format",
        u"Indicates that Security Directory Server log management and conversion to event format is supported.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.60",
        u"Encrypted Attribute Support",
        u"Server supports encrypted attributes.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.61",
        u"Proxy Monitor search",
        u"Server supports special monitor searches intended for proxy server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.63",
        u"SSHA Password Encrypt",
        u"Server supports SSHA Password Encryption.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.64",
        u"MD5 Password Encrypt",
        u"Server supports MD5 Password Encryption.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.65",
        u"Filter Replication",
        u"The server feature designed to have only required entries and a subset of its attributes to be replicated.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.66",
        u"Group Members Cache",
        u"Server supports caching group members.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.67",
        u"PKCS11 Support",
        u"Server supports PKCS11 Encryption standard.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.68",
        u"Server Admin Roles",
        u"Server supports Server Administration roles.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.69",
        u"Digest MD5 Support",
        u"Server supports Digest MD5 Bind.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.70",
        u"External Bind Support",
        u"Server supports External Bind.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.71",
        u"Persistent Search",
        u"Server supports persistent search.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.72",
        u"Admin Server Denial of Service Prevention",
        u"Admin Server supports Denial of Service Prevention.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.73",
        u"Admin server Enhanced Monitor Support",
        u"Admin server supports 'cn=monitor', 'cn=connections,cn=monitor', and 'cn=workers,cn=monitor' searches.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.74",
        u"Admin Server Support for Schema Searches",
        u"Admin server supports searches on schema.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.76",
        u"System Monitor Search",
        u"Server supports cn=system,cn=monitor search.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.77",
        u"Multiple Password Policies",
        u"Server allows multiple password policy to be defined and used.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.78",
        u"Passthrough Authentication",
        u"Server supports pass through authentication feature.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.79",
        u"Dynamic Updates of Replication Supplier Request",
        u"Server supports dynamic updates of replication supplier information.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.81",
        u"Audit Performance",
        u"Server supports auditing of performance for operations.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.82",
        u"No Emergency Thread Support",
        u"Emergency Thread is not supported by server.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.83",
        u"Enhanced Replication Group RI handling",
        u"Enhanced Replication Group RI handling",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.84",
        u"Reread the DB2® Password",
        u"Server re-reads the DB2 password to identify any change in DB2 password specified in configuration.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.85",
        u"Proxy Failback Based on Replication Queue",
        u"Proxy Server will failback only when replication queue is below the threshold specified in configuration file.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.86",
        u"Proxy Flow control",
        u"Proxy server supports flow control algorithm.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.87",
        u"Backup restore configuration capability",
        u"Server supports configuring automatic backup and restore.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.88",
        u"Password Policy Max Consecutive repeated characters",
        u"Server supports restricting maximum consecutive repeated characters in password policy.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.89",
        u"Virtual List View Support",
        u"Server supports virtual list view control in searches.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.90",
        u"Proxy Paged Search",
        u"Proxy Server supports paged control in searches.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.92",
        u"Tombstone Support",
        u"Server supports tombstone for deleted entries.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.93",
        u"Proxy Health Check outstanding limit",
        u"Proxy supports identifying a hung server based on the configured outstanding health check requests.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.94",
        u"Replication Finegrained timestamps",
        u"Replication uses fine grained timestamp for resolving conflicts.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.96",
        u"Distributed Dynamic group enabled",
        u"Proxy Server Supports enabling/Disabling Distributed dynamic group configuration option.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.97",
        u"Distributed group enabled",
        u"Proxy Server Supports enabling/Disabling Distributed group configuration option.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.99",
        u"SHA-2 support",
        u"Indicates that this server supports SHA-2 family of algorithms (only applicable for servers with database backend).",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.101",
        u"NIST SP800-131A Suite B",
        u"Indicates that the server supports Suite B mode.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.102",
        u"TLS 1.0 protocol",
        u"Indicates that the server supports TLS v1.0 protocol.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.103",
        u"TLS 1.1 protocol",
        u"Indicates that the server supports TLS v1.1 protocol.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.104",
        u"TLS 1.2 protocol",
        u"Indicates that the server supports TLS v1.2 protocol.",
        u"IBM Directory Server"),
    (
        "1.3.18.0.2.32.105",
        u"Replication of security attributes",
        u"Indicates that a read-only replica accepts the replication updates for password policy operational attributes.",
        u"IBM Directory Server"),

    ############################################################################
    # Found on OpenDS/OpenDJ
    ############################################################################

    (
        "1.3.6.1.4.1.26027.1.6.1",
        u"The password policy state extended operation",
        u"",
        u"OpenDS"),
    (
        "1.3.6.1.4.1.26027.1.6.2",
        u"The get connection ID extended operation",
        u"",
        u"OpenDS"),
    (
        "1.3.6.1.4.1.26027.1.6.3",
        u"The get symmetric key extended operation",
        u"",
        u"OpenDS"),
    (
        "1.3.6.1.4.1.26027.1.5.2",
        u"Replication Repair Control",
        u"",
        u"OpenDS"),

    ################# Misc #################

    (
        "1.3.6.1.4.1.21008.108.63.1",
        u"Session Tracking Control",
        u"",
        u"draft-wahl-ldap-session"
    ),

    ############################################################################
    # Found on ApacheDS
    ############################################################################

    (
        "1.3.6.1.4.1.18060.0.0.1",
        u"CascadeControl",
        u"",
        u"ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.1",
        u"LaunchDiagnosticUiRequest",
        u"",
        u"ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.2",
        u"LaunchDiagnosticUiResponse",
        u"",
        u"ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.3",
        u"GracefulShutdownRequest",
        u"",
        u"ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.4",
        u"GracefulShutdownResponse",
        u"",
        u"ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.5",
        u"GracefulDisconnect",
        u"",
        u"ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.6",
        u"StoredProcedureRequest",
        u"",
        u"ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.7",
        u"StoredProcedureResponse",
        u"",
        u"ApacheDS"),

    ################# Novell eDirectory 8.x #################
    # see http://developer.novell.com/documentation//ldapover/ldap_enu/data/a6ik7oi.html

    (
        "2.16.840.1.113719.1.27.103.7",
        u"GroupingControl",
        u"groups a set of write operations with a cookie received with CreateGroupingRequest",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.1",
        u"ndsToLdapResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.2",
        u"ndsToLdapRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.3",
        u"createNamingContextRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.4",
        u"createNamingContextResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.5",
        u"mergeNamingContextRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.6",
        u"mergeNamingContextResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.7",
        u"addReplicaRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.8",
        u"addReplicaResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.9",
        u"refreshLDAPServerRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.10",
        u"refreshLDAPServerResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.11",
        u"removeReplicaRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.12",
        u"removeReplicaResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.13",
        u"namingContextEntryCountRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.14",
        u"namingContextEntryCountResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.15",
        u"changeReplicaTypeRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.16",
        u"changeReplicaTypeResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.17",
        u"getReplicaInfoRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.18",
        u"getReplicaInfoResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.19",
        u"listReplicaRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.20",
        u"listReplicaResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.21",
        u"receiveAllUpdatesRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.22",
        u"receiveAllUpdatesResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.23",
        u"sendAllUpdatesRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.24",
        u"sendAllUpdatesResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.25",
        u"requestNamingContextSyncRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.26",
        u"requestNamingContextSyncResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.27",
        u"requestSchemaSyncRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.28",
        u"requestSchemaSyncResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.29",
        u"abortNamingContextOperationRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.30",
        u"abortNamingContextOperationResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.31",
        u"getContextIdentityNameRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.32",
        u"getContextIdentityNameResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.33",
        u"getEffectivePrivilegesRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.34",
        u"getEffectivePrivilegesResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.35",
        u"SetReplicationFilterRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.37",
        u"getReplicationFilterRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.39",
        u"createOrphanPartitionrequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.41",
        u"removeOrphanPartitionRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.43",
        u"triggerBKLinkerRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.45",
        u"triggerDRLProcessRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.47",
        u"triggerJanitorRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.49",
        u"triggerLimberRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.51",
        u"triggerSkulkerRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.53",
        u"triggerSchemaSyncRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.55",
        u"triggerPartitionPurgeRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.79",
        u"EventMonitorRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.84",
        u"filteredEventMonitorRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.103.1",
        u"createGroupingRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.103.2",
        u"endGroupingRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.1",
        u"Put Login Configuration",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.3",
        u"Get Login Configuration",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.5",
        u"Delete Login Configuration",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.7",
        u"Put Login Secret",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.9",
        u"Delete Login Secret",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.11",
        u"Set Universal Password",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.13",
        u"Get Universal Password",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.15",
        u"Delete Universal Password",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.17",
        u"Check password against password policy",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.2",
        u"SSLDAP_GET_SERVICE_INFO_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.4",
        u"SSLDAP_READ_SECRET_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.6",
        u"SSLDAP_WRITE_SECRET_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.8",
        u"SSLDAP_ADD_SECRET_ID_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.10",
        u"SSLDAP_REMOVE_SECRET_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.12",
        u"SSLDAP_REMOVE_SECRET_STORE_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.14",
        u"SSLDAP_ENUMERATE_SECRET_IDS_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.16",
        u"SSLDAP_UNLOCK_SECRETS_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.18",
        u"SSLDAP_SET_EP_MASTER_PASSWORD_REPLY",
        u"",
        u"Novell eDirectory (NDS)"),

    # LDAP Extensions Used by the Novell Import Convert Export Utility
    # LDAP Bulk Update Replication Protocol (LBURP)

    (
        "2.16.840.1.113719.1.142.100.1",
        u"startFramedProtocolRequest",
        u"",
        u"Novell eDirectory (NDS): draft-ietf-ldup-framing"),
    (
        "2.16.840.1.113719.1.142.100.2",
        u"startFramedProtocolResponse",
        u"",
        u"Novell eDirectory (NDS): draft-ietf-ldup-framing"),
    (
        "2.16.840.1.113719.1.142.100.3",
        u"ReplicationUpdate",
        u"",
        u"draft-ietf-ldup-protocol"),
    (
        "2.16.840.1.113719.1.142.100.4",
        u"endFramedProtocolRequest",
        u"",
        u"Novell eDirectory (NDS): draft-ietf-ldup-framing"),
    (
        "2.16.840.1.113719.1.142.100.5",
        u"endFramedProtocolResponse",
        u"",
        u"Novell eDirectory (NDS): draft-ietf-ldup-framing"),
    (
        "2.16.840.1.113719.1.142.100.6",
        u"lburpOperationRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.142.100.7",
        u"lburpOperationResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.96",
        u"LDAPBackupRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.97",
        u"LDAPBackupResponse",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.98",
        u"LDAPRestoreRequest",
        u"",
        u"Novell eDirectory (NDS)"),

    (
        "2.16.840.1.113719.1.27.100.101",
        u"DNStoX500DNRequest",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.102",
        u"DNStoX500DNResponse",
        u"",
        u"Novell eDirectory (NDS)"),


    (
        "2.16.840.1.113719.1.39.42.100.1",
        u"NMAS Put Login Configuration Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.3",
        u"NMAS Get Login Configuration Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.5",
        u"NMAS Delete Login Configuration Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.7",
        u"NMAS Put Login Secret Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.9",
        u"NMAS Delete Login Secret Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.11",
        u"NMAS Set Password Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.12",
        u"NMAS Set Password Response",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.13",
        u"NMAS Get Password Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.14",
        u"NMAS Get Password Response",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.15",
        u"NMAS Delete Password Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.17",
        u"NMAS Password Policy Check Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.19",
        u"NMAS Get Password Policy Info Request",
        u"",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.21",
        u"NMAS Change Password Request",
        u"Change (Universal?) Password",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.23",
        u"NMAS GAMS Request",
        u"NMAS Graded Authentication management",
        u"Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.25",
        u"NMAS management (new with NMAS 3.1.0)",
        u"",
        u"Novell eDirectory (NDS)"),

    # FreeIPA
    (
        "2.16.840.1.113730.3.8.10.6",
        u"OTPSyncRequest",
        u"OTP token synchronization request control",
        u"FreeIPA"),

    # OpenDJ/OpenAM
    (
        "1.3.6.1.4.1.36733.2.1.5.1",
        u"TransactionID request control",
        u"",
        u"OpenDJ/OpenAM"),

)


OID_REG = {}

def build_reg():
    """
    build the globally readable OID dictionary
    """
    global OID_REG
    for oid, name, desc, ref in OID_LIST:
        assert isinstance(oid, str), TypeError("Wrong type for 'oid' for OID %r" % (oid))
        assert isinstance(name, str), TypeError("Wrong type for 'name' for OID %r" % (oid))
        assert isinstance(desc, str), TypeError("Wrong type for 'description' for OID %r" % (oid))
        assert isinstance(ref, str), TypeError("Wrong type for 'reference' for OID %r" % (oid))
        if oid in OID_REG:
            logger.warning(
                'Double OID %r in web2ldap.ldaputil.oidreg.OID_LIST: %r vs. %r',
                oid,
                name,
                OID_REG[oid][0],
            )
        else:
            OID_REG[oid] = (name, desc, ref)
    logger.debug('Added %d items to web2ldap.ldaputil.oidreg.OID_REG', len(OID_REG))

build_reg()
