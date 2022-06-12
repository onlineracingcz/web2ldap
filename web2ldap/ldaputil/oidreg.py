# -*- coding: ascii -*-
"""
ldapoidreg - Simple dictionary registry for LDAP-related OIDs.

This is used in web2ldap to display further information about
LDAP-related OIDs (e.g. in RootDSE)

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

Comprehensive list initially contributed by Norbert Klasen
"""

from ..log import logger

OID_LIST = (

    # From https://www.iana.org/assignments/ldap-parameters
    (
        "1.2.826.0.1.3344810.2.3",
        "Matched Values Control",
        "",
        "RFC 3876"
    ),
    (
        "1.2.840.113556.1.4.473",
        "Server Side Sort Request",
        "",
        "RFC 2891"
    ),
    (
        "1.2.840.113556.1.4.474",
        "Server Side Sort Response",
        "",
        "RFC 2891"
    ),
    (
        "1.3.6.1.1.7.1",
        "LCUP Sync Request Control",
        "",
        "RFC 3928"
    ),
    (
        "1.3.6.1.1.7.2",
        "LCUP Sync Update Control",
        "",
        "RFC 3928"
    ),
    (
        "1.3.6.1.1.7.3",
        "LCUP Sync Done Control",
        "",
        "RFC 3928"
    ),
    (
        "1.3.6.1.1.8",
        "Cancel Operation",
        "",
        "RFC 3909"
    ),
    (
        "1.3.6.1.1.12",
        "Assertion Control",
        "",
        "RFC 4528"
    ),
    (
        "1.3.6.1.1.13.1",
        "LDAP Pre-read Control",
        "",
        "RFC 4527"
    ),
    (
        "1.3.6.1.1.13.2",
        "LDAP Post-read Control",
        "",
        "RFC 4527"
    ),
    (
        "1.3.6.1.1.14",
        "Modify-Increment",
        "",
        "RFC 4525"
    ),
    (
        "1.3.6.1.4.1.1466.20036",
        "Notice of disconnection",
        "",
        "RFC 4511"
    ),
    (
        "1.3.6.1.4.1.1466.101.119.1",
        "Dynamic Refresh",
        "Extended operation for requesting TTL refresh",
        "RFC 2589"
    ),
    (
        "1.3.6.1.4.1.1466.20037",
        "Start TLS",
        "Request to start Transport Layer Security.",
        "RFC 2830"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.1",
        "All Operational Attributes",
        "Provide a simple mechanism which clients may use to request the return of all operational attributes.",
        "RFC 3673"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.2",
        "OC AD Lists",
        "Return of all attributes of an object class",
        "RFC 4529"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.3",
        "True/False filters",
        "absolute True (&) and False (|) filters",
        "RFC 4526"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.4",
        "Language Tag Options",
        "storing attributes with language tag options in the DIT",
        "RFC 3866"
    ),
    (
        "1.3.6.1.4.1.4203.1.5.5",
        "Language Range Options",
        "language range matching of attributes with language tag options stored in the DIT",
        "RFC 3866"
    ),

    (
        "1.3.6.1.4.1.4203.1.9.1.1",
        "Sync Request Control",
        "syncrepl",
        "RFC 4533"
    ),
    (
        "1.3.6.1.4.1.4203.1.9.1.2",
        "Sync State Control",
        "syncrepl",
        "RFC 4533"
    ),
    (
        "1.3.6.1.4.1.4203.1.9.1.3",
        "Sync Done Control",
        "syncrepl",
        "RFC 4533"
    ),
    (
        "1.3.6.1.4.1.4203.1.9.1.4",
        "Sync Info Message",
        "syncrepl",
        "RFC 4533"
    ),

    (
        "1.3.6.1.4.1.4203.1.10.1",
        "Subentries",
        "",
        "RFC 3672"
    ),
    (
        "1.3.6.1.4.1.4203.1.11.1",
        "Modify Password",
        "modification of user passwords",
        "RFC 3062"
    ),
    (
        "1.3.6.1.4.1.4203.1.11.3",
        "Who am I?",
        "",
        "RFC 4532"
    ),
    (
        "2.16.840.1.113730.3.4.2",
        "ManageDsaIT",
        "",
        "RFC 3296"
    ),
    (
        "2.16.840.1.113730.3.4.15",
        "Authorization Identity Response Control",
        "Returned with bind requests to provide LDAP clients with the DN and authentication method used (useful when SASL or certificate mapping is employed).",
        "RFC 3829"
    ),
    (
        "2.16.840.1.113730.3.4.16",
        "Authorization Identity Request Control",
        "Can be provided with bind requests to indicate to the server that an Authentication Response Control is desired with the bind response.",
        "RFC 3829"
    ),

    (
        "1.2.826.0.1.334810.2.3",
        "valuesReturnFilter",
        "",
        "RFC 3876"),
    (
        "1.2.840.113549.6.0.0",
        "Signed Operation",
        "",
        "RFC 2649"),
    (
        "1.2.840.113549.6.0.1",
        "Demand Signed Result",
        "",
        "RFC 2649"),
    (
        "1.2.840.113549.6.0.2",
        "Signed Result",
        "",
        "RFC 2649"),
    (
        "1.2.840.113556.1.4.319",
        "Simple Paged Results",
        "Control for simple paging of search results",
        "RFC 2696"),

    # Transaction Control (see RFC 5805)
    (
        "1.3.6.1.1.21.1",
        "Start Transaction Request",
        "",
        "RFC 5805"),
    (
        "1.3.6.1.1.21.2",
        "Transaction Specification Request Control",
        "",
        "RFC 5805"),
    (
        "1.3.6.1.1.21.3",
        "End Transactions Request and Response",
        "",
        "RFC 5805"),

    # MS Active Directory and ADAM

    (
        '1.2.840.113556.1.4.417',
        'LDAP_SERVER_SHOW_DELETED_OID',
        'Show deleted control (Stateless)',
        'Platform SDK: DSML Services for Windows'),


    (
        '1.2.840.113556.1.4.521',
        'LDAP_SERVER_CROSSDOM_MOVE_TARGET_OID',
        'Cross-domain move control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.528',
        'LDAP_SERVER_NOTIFICATION_OID',
        'Server search notification control (Forbidden)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.529',
        'LDAP_SERVER_EXTENDED_DN_OID',
        'Extended DN control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.619',
        'LDAP_SERVER_LAZY_COMMIT_OID',
        'Lazy commit control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.801',
        'LDAP_SERVER_SD_FLAGS_OID',
        'Security descriptor flags control  (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        "1.2.840.113556.1.4.802",
        "SD_FLAGS",
        "Incremental Retrieval of Multi-valued Properties",
        "draft-kashi-incremental"),

    (
        '1.2.840.113556.1.4.805',
        'LDAP_SERVER_TREE_DELETE_OID',
        'Tree delete control  (Stateless)',
        'draft-armijo-ldap-treedelete'),

    (
        '1.2.840.113556.1.4.841',
        'LDAP_SERVER_DIRSYNC_OID',
        'Directory synchronization control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.970',
        '',
        'Get stats control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1338',
        'LDAP_SERVER_VERIFY_NAME_OID',
        'Verify name control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1339',
        'LDAP_SERVER_DOMAIN_SCOPE_OID',
        'Domain scope control (Stateless): instructs the DC not to generate any LDAP continuation references when performing an LDAP operation',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1340',
        'LDAP_SERVER_SEARCH_OPTIONS_OID',
        'Search options control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1413',
        'LDAP_SERVER_PERMISSIVE_MODIFY_OID',
        'Permissive modify control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1504',
        'LDAP_SERVER_ASQ_OID',
        'Attribute scoped query control (Stateless)',
        'Platform SDK: DSML Services for Windows'),

    (
        '1.2.840.113556.1.4.1781',
        'LDAP_SERVER_FAST_BIND_OID',
        'Fast concurrent bind extended operation (Forbidden)',
        'Platform SDK: DSML Services for Windows'),

    (
        "1.2.840.113556.1.4.1852",
        "LDAP_SERVER_QUOTA_CONTROL_OID",
        "The LDAP_SERVER_QUOTA_CONTROL_OID control is used to pass the SID of a security principal, whose quota is being queried, to the server in a LDAP search operation.",
        'Platform SDK: DSML Services for Windows'),

    (
        "1.2.840.113556.1.4.1907",
        "LDAP_SERVER_SHUTDOWN_NOTIFY_OID",
        "",
        ''),

    (
        "1.2.840.113556.1.4.1948",
        "LDAP_SERVER_RANGE_RETRIEVAL_NOERR_OID",
        "",
        ""
    ),

    (
        "1.2.840.113556.1.4.1974",
        "LDAP_SERVER_FORCE_UPDATE_OID",
        "force update to always generate a new stamp for the attribute or link value and always replicate",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.1341",
        "LDAP_SERVER_RODC_DCPROMO_OID",
        "",
        ""
    ),

    (
        "1.2.840.113556.1.4.2026",
        "LDAP_SERVER_INPUT_DN_OID",
        "",
        ""
    ),

    (
        "1.2.840.113556.1.4.2064",
        "LDAP_SERVER_SHOW_RECYCLED_OID",
        "specify that tombstones, deleted-objects, and recycled-objects should be visible to the operation",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2065",
        "LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID",
        "specify that link attributes that refer to deleted-objects are visible to the search operation",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2066",
        "LDAP_SERVER_POLICY_HINTS_OID",
        "makes every password set operation to fully honour password policy",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2090",
        "LDAP_SERVER_DIRSYNC_EX_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2204",
        "LDAP_SERVER_TREE_DELETE_EX_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2205",
        "LDAP_SERVER_UPDATE_STATS_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2206",
        "LDAP_SERVER_SEARCH_HINTS_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2211",
        "LDAP_SERVER_EXPECTED_ENTRY_COUNT_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2237",
        "LDAP_CAP_ACTIVE_DIRECTORY_W8_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2239",
        "LDAP_SERVER_POLICY_HINTS_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2255",
        "LDAP_SERVER_SET_OWNER_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.2.840.113556.1.4.2256",
        "LDAP_SERVER_BYPASS_QUOTA_OID",
        "",
        "MS Active Directory"
    ),

    (
        "1.3.6.1.4.1.1466.29539.1",
        "LDAP_CONTROL_ATTR_SIZELIMIT",
        "",
        ""),
    (
        "1.3.6.1.4.1.1466.29539.2",
        "LDAP_CONTROL_NO_COPY",
        "",
        ""),
    (
        "1.3.6.1.4.1.1466.29539.3",
        "LDAP_CONTROL_PARTIAL_COPY",
        "",
        ""),
    (
        "1.3.6.1.4.1.1466.29539.5",
        "LDAP_CONTROL_NO_CHAINING",
        "",
        ""),
    (
        "1.3.6.1.4.1.1466.29539.7",
        "LDAP_CONTROL_ALIAS_ON_UPDATE",
        "",
        ""),
    (
        "1.3.6.1.4.1.1466.29539.10",
        "LDAP_CONTROL_TRIGGER",
        "",
        ""),
    (
        "1.3.6.1.4.1.1466.29539.12",
        "Chained request control",
        "Control included with iPlanet Directory Server prevents loops.",
        "iPlanet Directory Server 5.0 Administrator's Guide"),

    # Syntegra X.500 controls
    # see https://www.openldap.org/lists/ietf-ldapext/200010/msg00127.html
    (
        "2.16.840.1.113531.18.2.1",
        "LDAP_C_SETOPTIONS_OID",
        "",
        ""),
    (
        "2.16.840.1.113531.18.2.2",
        "LDAP_C_SETDONTUSECOPY_OID",
        "",
        ""),
    (
        "2.16.840.1.113531.18.2.3",
        "LDAP_C_SETLOCALSCOPE_OID",
        "",
        ""),
    (
        "2.16.840.1.113531.18.2.4",
        "LDAP_C_SETOPERATTR_OID",
        "Return operational attributes as well as user attributes",
        ""),
    (
        "2.16.840.1.113531.18.2.5",
        "LDAP_C_SETSUBENTRIES_OID",
        "Return only subentries",
        ""),
    (
        "2.16.840.1.113531.18.2.6",
        "LDAP_C_SETUSEALIAS_OID",
        "",
        ""),
    (
        "2.16.840.1.113531.18.2.7",
        "LDAP_C_SETPREFERCHAIN_OID",
        "",
        ""),
    (
        "2.16.840.1.113531.18.2.8",
        "LDAP_C_SETX500DN_OID",
        "",
        ""),
    (
        "2.16.840.1.113531.18.2.9",
        "LDAP_C_SETCOPYSHALLDO_OID",
        "",
        ""),
    (
        "2.16.840.1.113531.18.2.10",
        "LDAP_C_SETDONTMAPATTRS_OID",
        "",
        ""),
    (
        "2.16.840.1.113531.18.2.11",
        "LDAP_C_SETALLENTRIES_OID",
        "Return normal entries as well as sub-entries",
        ""),

    (
        "2.16.840.1.113719.1.27.101.1",
        "Duplicate Entry Request",
        "",
        "draft-ietf-ldapext-ldapv3-dupent"),
    (
        "2.16.840.1.113719.1.27.101.2",
        "DuplicateSearchResult",
        "",
        "draft-ietf-ldapext-ldapv3-dupent"),
    (
        "2.16.840.1.113719.1.27.101.3",
        "DuplicateEntryResponseDone",
        "",
        "draft-ietf-ldapext-ldapv3-dupent"),
    (
        "2.16.840.1.113719.1.27.101.5",
        "Simple Password",
        "not yet documented",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.101.6",
        "Forward Reference",
        "not yet documented",
        "NDS"),

    (
        "2.16.840.1.113719.1.27.101.40",
        "LDAP_CONTROL_SSTATREQUEST control",
        "not yet documented",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.101.41",
        "",
        "not yet documented",
        "NDS"),
    (
        "2.16.840.1.113719.1.14.100.91",
        "GetNamedPasswordRequest",
        "not yet documented",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.101.57",
        "VLV result count control",
        "not yet documented",
        "NDS"),

    (
        "2.16.840.1.113730.3.4.3",
        "Persistent Search",
        "",
        "draft-ietf-ldapext-psearch"),
    (
        "2.16.840.1.113730.3.4.4",
        "Password Change After Reset",
        "an octet string to indicate the user should change his password",
        "draft-vchu-ldap-pwd-policy"),
    (
        "2.16.840.1.113730.3.4.5",
        "Password Expiration Warning",
        "an octet string to indicate the time in seconds until the password expires",
        "draft-vchu-ldap-pwd-policy"),
    (
        "2.16.840.1.113730.3.4.6",
        "Netscape NT Synchronization Client",
        "",
        ""),
    (
        "2.16.840.1.113730.3.4.7",
        "Entry Change Request",
        "This control provides additional information about the change the caused a particular entry to be returned as the result of a persistent search.",
        "draft-ietf-ldapext-psearch"),
    (
        "2.16.840.1.113730.3.4.9",
        "Virtual List View Request",
        "",
        "draft-ietf-ldapext-ldapv3-vlv"),
    (
        "2.16.840.1.113730.3.4.10",
        "Virtual List View Response",
        "",
        "draft-ietf-ldapext-ldapv3-vlv"),
    (
        "2.16.840.1.113730.3.4.11",
        "Transaction ID Response",
        "",
        "http://docs.iplanet.com/docs/manuals/directory.html"),
    (
        "2.16.840.1.113730.3.4.12",
        "Proxied Authorization",
        "allows LDAP clients to use different credentials, without rebinding, when executing LDAP operations.",
        "draft-weltman-ldapv3-proxy"),
    (
        "2.16.840.1.113730.3.4.13",
        "iPlanet Directory Server Replication Update Information",
        "",
        " http://docs.iplanet.com/docs/manuals/directory.html"),
    (
        "2.16.840.1.113730.3.4.14",
        "Specific Backend Search Request",
        "iPlanet Directory Server search on specific backend",
        "http://docs.iplanet.com/docs/manuals/directory.html"),
    (
        "2.16.840.1.113730.3.4.17",
        "Real Attributes Only",
        "This control requests that the server only return attributes which are truly contained in the entries returned and that no resolution of virtual attributes be performed (such as defined by class of service and roles).",
        "http://docs.iplanet.com/docs/manuals/directory.html"),
    (
        "2.16.840.1.113730.3.4.18",
        "Proxied Authorization",
        "For assuming the identity of another entry for the duration of a request.",
        "RFC 4370"),

    (
        "2.16.840.1.113730.3.4.20",
        "Search on one backend",
        "",
        ""),


    # Various extensions defined in Internet drafts
    (
        "1.2.826.0.1.3344810.2.0",
        "Families of Entries",
        "",
        "draft-ietf-ldapext-families"
    ),

    #LDAP Server Profiles
    #attribute: ogSupportedProfile
    #http://www.opengroup.org/orc/DOCS/LDAP_PR/text/apdxa.htm
    (
        "1.2.826.0.1050.11.1.1",
        "Read-Only LDAP Server",
        "",
        "Open Group LDAP Server Profiles"),
    (
        "1.2.826.0.1050.11.2.1",
        "Read-Write LDAP Server",
        "",
        "Open Group LDAP Server Profiles"),
    (
        "1.2.826.0.1050.11.3.1",
        "White Pages Application LDAP Server",
        "",
        "Open Group LDAP Server Profiles"),
    (
        "1.2.826.0.1050.11.4.1",
        "Certificate Application LDAP Server",
        "",
        "Open Group LDAP Server Profiles"),
    (
        "1.2.826.0.1050.11.5.1",
        "Single Sign On Application LDAP Server",
        "",
        "Open Group LDAP Server Profiles"),

    (
        "2.16.840.1.113719.1.27.100.36",
        "setReplicationFilterResponse",
        "Set Replication Filter Response",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.38",
        "getReplicationFilterResponse",
        "Get Replication Filter Response",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.40",
        "createOrphanNamingContextResponse",
        "Create Orphan Partition Response",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.42",
        "removeOrphanNamingContextResponse",
        "Remove Orphan Partition Response",
        "NDS"),

    (
        "2.16.840.1.113719.1.27.100.44",
        "Trigger Backlinker Response",
        "",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.48",
        "Trigger Janitor Response",
        "",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.50",
        "Trigger Limber Response",
        "",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.52",
        "Trigger Skulker Response",
        "",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.54",
        "Trigger Schema Synch Response",
        "",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.56",
        "Trigger Partition Purge Response",
        "",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.80",
        "Monitor Events Response",
        "",
        "NDS"),
    (
        "2.16.840.1.113719.1.27.100.81",
        "Event Notification",
        "",
        "NDS"),

    (
        "2.16.840.1.113719.1.27.99.1",
        "Superior References",
        "",
        "Novell eDirectory 8.7+"),

    # DirXML-related OIDs, see http://developer.novell.com/documentation/dirxml/dirxmlbk/api/index.html

    (
        "2.16.840.1.113719.1.14.100.1",
        "GetDriverSetRequest",
        "Get the DN of the DirXML-DriverSet object associated with the server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.2",
        "GetDriverSetResponse",
        "The response for the GetDriverSetRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.3",
        "SetDriverSetRequest",
        "Set the DirXML-DriverSet object associated with a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.5",
        "ClearDriverSetRequest",
        "LDAP extension used to disassociate any DirXML driver set associated with a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.7",
        "GetDriverStartOptionRequest",
        "Get the start option value of a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.8",
        "GetDriverStartOptionResponse",
        "The response for the GetDriverStartOptionRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.9",
        "SetDriverStartOptionRequest",
        "Set the start option value of a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.11",
        "GetVersionRequest",
        "Get the version number of the DirXML engine associated with the server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.12",
        "GetVersionResponse",
        "The response for the GetVersionRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.13",
        "GetDriverStateRequest",
        "Get the current state of a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.14",
        "GetDriverStateResponse",
        "The response for the GetDriverStateRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.15",
        "StartDriverRequest",
        "Start a DirXML driver.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.17",
        "StopDriverRequest",
        "Stop a DirXML driver.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.19",
        "GetDriverStatsRequest",
        "Get an XML document describing the current state of a DirXML driver on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.20",
        "GetDriverStatsResponse",
        "The response for the GetDriverStatsRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.21",
        "DriverGetSchemaRequest",
        "Cause a DirXML driver to obtain its application's schema and store the schema in the DirXML-ApplicationSchema attribute on the DirXML-Driver object.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.23",
        "DriverResyncRequest",
        "Initiate a resync for a DirXML driver on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.25",
        "MigrateAppRequest",
        "Start a migrate from application for a DirXML driver on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.27",
        "QueueEventRequest",
        "Queue an event document for a DirXML driver on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.29",
        "SubmitCommandRequest",
        "Submit a command document to a DirXML driver on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.30",
        "SubmitCommandResponse",
        "The response for the SubmitCommandRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.31",
        "SubmitEventRequest",
        "Submit an event document to a DirXML driver on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.32",
        "SubmitEventResponse",
        "The response for the SubmitEventRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.33",
        "GetChunkedResultRequest",
        "Get part of a large result that is created in response to another data request.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.34",
        "GetChunkedResultResponse",
        "The response for the GetChunkedResultRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.35",
        "CloseChunkedResultRequest",
        "Clean up any resources associated with a large result that is created in response to another data request.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.37",
        "CheckObjectPasswordRequest",
        "LDAP request to check the nspmDistributionPassword value of an eDirectory object against the object's associated password in a connected system.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.38",
        "CheckObjectPasswordResponse",
        "The response for the CheckObjectPasswordRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.39",
        "InitDriverObjectRequest",
        "Instruct the DirXML Engine to initialize a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.41",
        "DeleteCacheEntriesRequest",
        "Delete event records from the cache of a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.45",
        "GetPasswordsStateRequest",
        "Get the state of passwords associated with a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.46",
        "GetPasswordsStateResponse",
        "The response for the GetPasswordsStateRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.47",
        "RegenerateKeyRequest",
        "Cause the DirXML Engine to regenerate the public key/private key pair used for encrypting data when setting passwords.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.49",
        "GetServerCertRequest",
        "Get the DirXML server's public key certificate that is used for encrypting data when setting passwords.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.50",
        "GetServerCertResponse",
        "The response for the GetServerCertRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.51",
        "DiscoverJobsRequest",
        "Discover available job definitions on a DirXML server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.52",
        "DiscoverJobsResponse",
        "The response for the DiscoverJobsRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.53",
        "NotifyJobUpdateRequest",
        "Notify the DirXML Engine that the data associated with a DirXML-Job object has changed.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.55",
        "StartJobRequest",
        "Cause the the DirXML Engine to start a job.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.57",
        "AbortJobRequest",
        "LDAP request to cause the the DirXML Engine to abort a running job.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.59",
        "GetJobStateRequest",
        "Get the state of a DirXML job.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.60",
        "GetJobStateResponse",
        "The response for the GetJobStateRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.61",
        "CheckJobConfigRequest",
        "LDAP request to get a report on the configuration of a DirXML job.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.62",
        "CheckJobConfigResponse",
        "The response for the CheckJobConfigRequest request.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.63",
        "SetLogEventsRequest",
        "Set the filter for reporting events in the DirXML Engine to the logging service.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.65",
        "ClearLogEventsRequest",
        "LDAP extension used to clear the event reporting filter used by the DirXML Engine to determine which events to report to the logging service.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.67",
        "SetAppPasswordRequest",
        "Set the application password for a DirXML-Driver object associated with a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.69",
        "ClearAppPasswordRequest",
        "LDAP extension used to clear the application password for a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.71",
        "SetRemoteLoaderPasswordRequest",
        "Set the remote loader password for a DirXML-Driver object associated with a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.73",
        "ClearRemoteLoaderPasswordRequest",
        "LDAP extension used to clear the Remote Loader password for a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.75",
        "SetNamedPasswordRequest",
        "Set a named password for an eDirectory object associated with a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.77",
        "RemoveNamedPasswordRequest",
        "Remove a named password from an eDirectory object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.79",
        "RemoveAllNamedPasswordsRequest",
        "Remove all named passwords from an eDirectory object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.81",
        "ListNamedPasswordsRequest",
        "List any named passwords from an eDirectory object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.82",
        "ListNamedPasswordsResponse",
        "The response for the ListNamedPasswordsRequest operation.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.41",
        "ViewCacheEntriesRequest",
        "View event records in the cache of a DirXML-Driver object on a server.",
        "Novell DirXML",
    ),

    (
        "2.16.840.1.113719.1.14.100.42",
        "ViewCacheEntriesResponse",
        "The response for the ViewCacheEntriesRequest operation.",
        "Novell DirXML",
    ),



    (
        "1.3.6.1.4.1.4203.1.10.2",
        "No-Op Control",
        "",
        "draft-zeilenga-ldap-noop"),
    (
        "1.3.6.1.4.1.4203.1.11.2",
        "LDAP Cancel Extended Operation",
        "",
        "RFC 3909"),

    # See https://www.openldap.org/faq/data/cache/212.html
    (
        "1.3.6.1.4.1.4203.666.5.1",
        "Subentries Control",
        "not valid anymore",
        "draft-zeilenga-ldap-subentry"),
    (
        "1.3.6.1.4.1.4203.666.5.2",
        "No-Op Control",
        "experimental OID - not valid anymore",
        "draft-zeilenga-ldap-noop"),

    # OpenLDAP's ldap.h - various works in progress
    (
        "1.3.6.1.4.1.4203.666.5.9",
        "LDAP_CONTROL_ASSERT",
        "",
        "OpenLDAP's ldap.h: various works in progress"),
    (
        "1.3.6.1.4.1.4203.666.5.10.1",
        "LDAP_CONTROL_PRE_READ",
        "",
        "OpenLDAP's ldap.h: various works in progress"),
    (
        "1.3.6.1.4.1.4203.666.5.10.2",
        "LDAP_CONTROL_POST_READ",
        "",
        "OpenLDAP's ldap.h: various works in progress"),
    (
        "1.3.6.1.4.1.4203.666.11.3",
        "Chaining Behavior",
        "",
        "draft-sermersheim-ldap-chaining"),
    (
        "1.3.6.1.4.1.4203.666.5.11",
        "LDAP_CONTROL_NO_SUBORDINATES",
        "",
        "OpenLDAP's ldap.h: various works in progress"),
    (
        "1.3.6.1.4.1.4203.666.5.12",
        "Relax Rules Control",
        "",
        "draft-zeilenga-ldap-relax, see also OpenLDAP's ldap.h"),
    (
        "1.3.6.1.4.1.4203.666.5.14",
        "Values Sort Control",
        "",
        "OpenLDAP's ldap.h: OpenLDAP Experimental Features"),
    (
        "1.3.6.1.4.1.4203.666.5.15",
        "Don't Use Copy Control",
        "",
        "OpenLDAP's ldap.h: OpenLDAP Experimental Features"),
    (
        "1.3.6.1.1.22",
        "Don't Use Copy Control",
        "The requested operation MUST NOT be performed on copied information.",
        "RFC 6171"),

    (
        "1.3.6.1.4.1.4203.666.5.17",
        "What Failed? Control",
        "",
        "draft-masarati-ldap-whatfailed"),
    # see https://bugs.openldap.org/show_bug.cgi?id=6598
    (
        "1.3.6.1.4.1.4203.666.5.18",
        "No-Op Search Control",
        "",
        "OpenLDAP ITS#6598"),

    # OpenLDAP's ldap.h: LDAP Experimental (works in progress) Features
    (
        "1.3.6.1.4.1.4203.666.8.2",
        "LDAP_FEATURE_MODIFY_INCREMENT",
        "",
        "OpenLDAP's ldap.h: OpenLDAP Experimental Features"),
    (
        "1.3.6.1.4.1.4203.666.8.1",
        "LDAP_FEATURE_SUBORDINATE_SCOPE",
        "",
        "OpenLDAP's ldap.h: OpenLDAP Experimental Features"),

    # LDAP Transactions (draft-zeilenga-ldap-txn)
    # See https://www.openldap.org/faq/data/cache/1330.html
    (
        "1.3.6.1.4.1.4203.666.11.7.1",
        "",
        "LDAP Transactions Extended Operation",
        "OpenLDAP's ldap.h: OpenLDAP Experimental Features (draft-zeilenga-ldap-txn)"),
    (
        "1.3.6.1.4.1.4203.666.11.7.2",
        "",
        "LDAP Transactions Extended Control",
        "OpenLDAP's ldap.h: OpenLDAP Experimental Features (draft-zeilenga-ldap-txn)"),
    (
        "1.3.6.1.4.1.4203.666.11.7.3",
        "",
        "LDAP Transactions Extended Operation",
        "OpenLDAP's ldap.h: OpenLDAP Experimental Features (draft-zeilenga-ldap-txn)"),

    # See https://www.openldap.org/faq/data/cache/1280.html
    (
        "1.3.6.1.4.1.4203.666.11.6.1",
        "chainedRequest",
        "",
        "draft-sermersheim-ldap-distproc"),
    (
        "1.3.6.1.4.1.4203.666.11.6.2",
        "canChainOperations",
        "",
        "draft-sermersheim-ldap-distproc"),
    (
        "1.3.6.1.4.1.4203.666.11.6.3",
        "returnContinuationReference",
        "",
        "draft-sermersheim-ldap-distproc"),

    (
        "1.3.6.1.4.1.4203.666.11.9.5.1",
        "Proxy cache privateDB control",
        "Allows regular LDAP operations with respect to the private database instead of the proxied one.",
        "OpenLDAP Experimental Features"),
    (
        "1.3.6.1.4.1.4203.666.11.9.6.1",
        "Proxy cache queryDelete ext.op.",
        "",
        "OpenLDAP Experimental Features"),
    (
        "1.3.6.1.4.1.4203.666.5.16",
        "LDAP Dereference Control",
        "This control is intended to collect extra information related to cross-links present in entries returned as part of search responses.",
        "draft-masarati-ldap-deref"),

    (
        "1.3.6.1.4.1.4203.666.6.5",
        "LDAP Verify Credentials operation",
        "",
        "OpenLDAP Experimental Features"),

    # draft-behera-ldap-password-policy
    (
        "1.3.6.1.4.1.42.2.27.8.5.1",
        "passwordPolicyRequest",
        "A control to request for requesting / receiving information about password policy",
        "draft-behera-ldap-password-policy"),

    (
        "2.16.840.1.113730.3.5.3",
        "iPlanet Start Replication Request Extended Operation",
        "",
        "iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.4",
        "iPlanet Replication Response Extended Operation",
        "",
        "iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.5",
        "iPlanet End Replication Request Extended Operation",
        "",
        "iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.6",
        "iPlanet Replication Entry Request Extended Operation",
        "",
        "iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.7",
        "iPlanet Bulk Import Start Extended Operation",
        "",
        "iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.8",
        "iPlanet Bulk Import Finished Extended Operation",
        "",
        "iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.9",
        "iPlanet Digest Authentication Calculation Extended Operation",
        "",
        "iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.10",
        "iPlanet Distributed Numeric Assignment Request",
        "",
        "iPlanet Directory 5.0+"),
    (
        "2.16.840.1.113730.3.5.11",
        "iPlanet Distributed Numeric Assignment Response",
        "",
        "iPlanet Directory 5.0+"),

    (
        "2.16.840.1.113730.3.4.19",
        "iPlanet Virtual Attributes Only",
        "",
        "iPlanet Directory 5.0+"),

    (
        "1.3.6.1.4.1.42.2.27.9.5.2",
        "Get Effective Rights",
        "",
        "iPlanet Directory 5.0+"),
    (
        "1.3.6.1.4.1.42.2.27.9.5.8",
        "Account Usability Control",
        "Determine whether a user account may be used for authenticating to the server.",
        "iPlanet Directory 5.0+"),

    # supportedCapabilities
    # http://msdn.microsoft.com/en-us/library/cc223359(PROT.13).aspx
    (
        "1.2.840.113556.1.4.800",
        "LDAP_CAP_ACTIVE_DIRECTORY_OID",
        "This LDAP server is an Active Directory server (Windows 2000 and later).",
        "Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1670",
        "LDAP_CAP_ACTIVE_DIRECTORY_V51_OID",
        "This LDAP server is a 'Whistler' Active Directory server (Windows 2003 and later).",
        "Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1791",
        "LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID",
        "This LDAP server is supports signing and sealing on an NTLM authenticated connection, and is capable of performing subsequent binds on such a connection.",
        "Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1935",
        "LDAP_CAP_ACTIVE_DIRECTORY_V60_OID",
        "Windows Server 2008 AD DS and Windows Server 2008 AD LDS",
        "Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1880",
        "LDAP_CAP_ACTIVE_DIRECTORY_ADAM_DIGEST",
        "DC accepts DIGEST-MD5 binds for AD LDSsecurity principals",
        "Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1851",
        "LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID",
        "",
        "Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.1920",
        "LDAP_CAP_ACTIVE_DIRECTORY_PARTIAL_SECRETS_OID",
        "indicates that the DC is an RODC",
        "Microsoft Active Directory"),
    (
        "1.2.840.113556.1.4.2080",
        "LDAP_CAP_ACTIVE_DIRECTORY_V61_R2_OID",
        "Windows Server 2008R2 AD DS and Windows Server 2008R2 AD LDS",
        "Microsoft Active Directory"),

    # draft-ietf-ldup-subentry-07.txt
    (
        "1.3.6.1.4.1.7628.5.101.1",
        "ldapSubentriesControl",
        "",
        "draft-ietf-ldup-subentry"),

    # SunONE Directory Server 5.2+
    (
        "1.3.6.1.4.1.42.2.27.9.6.1",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.2",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.3",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.4",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.5",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.6",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.7",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.8",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.9",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.11",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.12",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.13",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.14",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.15",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.16",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.17",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.18",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.19",
        "",
        "Replication Protocol related.",
        "SunONE Directory Server 5.2+"),

    (
        "1.3.6.1.4.1.42.2.27.9.6.21",
        "",
        "???",
        "SunONE Directory Server 5.2+"),
    (
        "1.3.6.1.4.1.42.2.27.9.6.22",
        "",
        "???",
        "SunONE Directory Server 5.2+"),

    ############################################################################
    # IBM Directory Server
    # see http://www-01.ibm.com/support/knowledgecenter/api/content/nl/en/SSVJJU_6.3.1/com.ibm.IBMDS.doc_6.3.1/admin_gd517.htm
    ############################################################################

    # ACI mechanisms

    (
        "1.3.18.0.2.26.2",
        "IBM SecureWay V3.2 ACL Model",
        "Indicates that the LDAP server supports the IBM SecureWay V3.2 ACL model",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.26.3",
        "IBM Filter Based ACL Mechanism",
        "Indicates that the LDAP server supports IBM Directory Server v5.1 filter based ACLs.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.26.4",
        "System Restricted ACL Support",
        "Server supports specification and evaluation of ACLs on system and restricted attributes.",
        "IBM Directory Server"),

    # Extended operations

    (
        "1.3.18.0.2.12.58",
        "Account status extended operation",
        "This extended operation sends the server a DN of an entry which contains a userPassword attribute, and the server sends back the status of the user account being queried:open, locked or expired",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.46",
        "Attribute type extended operations",
        "Retrieve attributes by supported capability: operational, language tag, attribute cache, unique or configuration.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.5",
        "Begin transaction extended operation",
        "Begin a Transactional context.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.15",
        "Cascading replication operation extended operation",
        "This operation performs the requested action on the server it is issued to and cascades the call to all consumers beneath it in the replication topology.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.20",
        "Clear log extended operation",
        "Request to Clear log file.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.16",
        "Control replication extended operation",
        "This operation is used to force immediate replication, suspend replication, or resume replication by a supplier. This operation is allowed only when the client has update authority to the replication agreement",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.17",
        "Control queue extended operation",
        'This operation marks items as "already replicated" for a specified agreement. This operation is allowed only when the client has update authority to the replication agreement.',
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.30",
        "DN normalization extended operation",
        "Request to normalize a DN or a sequence of DNs.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.40",
        "Dynamic server trace extended operation",
        "Activate or deactivate tracing in the IBM Tivoli Directory Server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.28",
        "Update configuration extended operation",
        "Request to update server configuration for IBM Tivoli Directory Server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.6",
        "End transaction extended operation",
        "End Transactional context (commit/rollback),.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.1",
        "Event notification register request extended operation",
        "Request registration for events notification.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.3",
        "Event notification unregister request extended operation",
        "Unregister for events that were registered for using an Event Registration Request.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.22",
        "Get lines extended operation",
        "Request to get lines from a log file.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.24",
        "Get number of lines extended operation",
        "Request number of lines in a log file.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.50",
        "Group evaluation extended operation",
        "Requests all the groups that a given user belongs to.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.35",
        "Kill connection extended operation",
        "Request to kill connections on the server. The request can be to kill all connections or kill connections by bound DN, IP, or a bound DN from a particular IP.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.41",
        "LDAP trace facility extended operation",
        "Use this extended operation to control LDAP Trace Facility remotely using the Admin Daemon.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.19",
        "Quiesce or unquiesce replication context extended operation",
        "This operation puts the subtree into a state where it does not accept client updates (or terminates this state),, except for updates from clients authenticated as directory administrators where the Server Administration control is present.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.56",
        "Replication error log extended operation",
        "Maintenance of a replication error table.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.54",
        "Replication topology extended operation",
        "Trigger a replication of replication topology-related entries under a given replication context.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.26",
        "Start, stop server extended operations",
        "Request to start, stop or restart an LDAP server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.44",
        "Unique attributes extended operation",
        "Feature to enforce attribute uniqueness.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.31",
        "Update event notification extended operation",
        "Request that the event notification plug-in get the updated configuration from the server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.32",
        "Update log access extended operation",
        "Request that the log access plug-in get the updated configuration from the server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.37",
        "User type extended operation",
        "Request to get the User Type of the bound user.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.64",
        "Prepare transaction extended operation",
        "Requests the server to start processing the operations sent in a transaction.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.74",
        "Online backup extended operation",
        "Perform online backup of the directory server instance's database.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.75",
        "Effective password policy extended operation",
        "Query effective password policy for a user or a group.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.79",
        "Password policy bind initialize and verify extended operation",
        "Performs password policy bind initialization and verification for a specified user.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.80",
        "Password policy finalize and verify bind extended operation",
        "Performs password policy post-bind processing for a specified user.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.73",
        "Get file extended operation",
        "Return the contents of a given file on the server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.12.70",
        "LogMgmtControl extended operation",
        "Start, stop, or query the status of the log management.",
        "IBM Directory Server"),

    # Extended controls

    (
        "1.3.18.0.2.10.28",
        "AES bind control",
        "This control enables the IBM Tivoli Directory Server to send updates to the consumer server with passwords already encrypted using AES.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.22",
        "Audit control",
        "The control sends a sequence of uniqueid strings and a source ip string to the server. When the server receives the control, it audits the list of uniqueids and sourceip in the audit record of the operation.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.23",
        "Do not replicate control",
        "This control can be specified on an update operation (add, delete, modify,modDn, modRdn).",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.21",
        "Group authorization control",
        "The control sends a list of groups that a user belongs to.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.25",
        "Modify groups only control",
        "Attached to a delete or modify DN request to cause the server to do only the group referential integrity processing for the delete or rename request without doing the actual delete or rename of the entry itself. The entry named in the delete or modify DN request does not need to exist on the server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.27",
        "No replication conflict resolution control",
        "When present, a replica server accepts a replicated entry without trying to resolve any replication conflict for this entry.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.26",
        "Omit group referential integrity control",
        "Omits the group referential integrity processing on a delete or modrdn request.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.24",
        "Refresh entry control",
        "This control is returned when a target server detects a conflict (T0!=T2 & T1>T2) during a replicated modify operation.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.18",
        "Replication supplier bind control",
        "This control is added by the supplier, if the supplier is a gateway server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.29",
        "Replication update ID control",
        "This control was created for serviceability. If the supplier server is set to issue the control, each replicated update is accompanied by this control.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.15",
        "Server administration control",
        "Allows an update operation by the administrator under conditions when the operation would normally be refused (server is quiesced, a read-only replica, etc.)",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.5",
        "Transaction control",
        "Marks the operation as part of a transactional context.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.30",
        "Limit number of attribute values control",
        "Limit the number of attribute values returned for an entry in a search operation.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.32",
        "Delete operation timestamp control",
        "Send the modified timestamp values to a replica during a delete operation.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.10.33",
        "Return deleted objects control",
        "Return all entries in the database including those with (isDeleted=TRUE).",
        "IBM Directory Server"),

    # Supported and enabled capabilities

    (
        "1.3.18.0.2.32.1",
        "Enhanced Replication Model",
        "Identifies the replication model introduced in IBM Directory Server v5.1 including subtree and cascading replication.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.2",
        "Entry Checksum",
        "Indicates that this server supports the ibm-entrychecksum and ibm-entrychecksumop features.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.3",
        "Entry UUID",
        "This value is listed in the ibm-capabilities Subentry for those suffixes that support the ibm-entryuuid attribute.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.4",
        "Filter ACLs",
        "Identifies that this server supports the IBM Filter ACL model",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.5",
        "Password Policy",
        "Identifies that this server supports password policies",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.6",
        "Sort by DN",
        "Enables searches sorted by DNs in addition to regular attributes.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.8",
        "Administration Group Delegation",
        "Server supports the delegation of server administration to a group of administrators that are specified in the configuration backend.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.9",
        "Denial of Service Prevention",
        "Server supports the denial of service prevention feature, including read/write time-outs and the emergency thread.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.10",
        "Dereference Alias Option",
        "Server supports an option to not dereference aliases by default",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.11",
        "Admin Daemon Audit Logging",
        "Server supports the auditing of the admin daemon.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.12",
        "128 Character Table Names",
        "The server feature to allow name of unique attributes to be higher than 18 characters (with the maximum of 128 characters).",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.13",
        "Attribute Caching Search Filter Resolution",
        "The server supports attribute caching for search filter resolution.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.14",
        "Dynamic Tracing",
        "Server supports active tracing for the server with an LDAP extended operation.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.15",
        "Entry And Subtree Dynamic Updates",
        "The server supports dynamic configuration updates on entries and subtrees.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.16",
        "Globally Unique Attributes",
        "The server feature to enforce globally unique attribute values.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.17",
        "Group-Specific Search Limits",
        "Supports extended search limits for a group of people.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.18",
        "IBMpolicies Replication Subtree",
        "Server supports the replication of the cn=IBMpolicies subtree.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.19",
        "Max Age ChangeLog Entries",
        "Specifies that the server is capable of retaining changelog entries based on age.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.20",
        "Monitor Logging Counts",
        "The server provides monitor logging counts for messages added to server, command-line interface, and audit log files.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.21",
        "Monitor Active Workers Information",
        "The server provides monitor information for active workers (cn=workers,cn=monitor).",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.22",
        "Monitor Connection Type Counts",
        "The server provides monitor connection type counts for SSL and TLS connections.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.23",
        "Monitor Connections Information",
        "The server provides monitor information for connections by IP address instead of connection ID (cn=connections, cn=monitor)",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.24",
        "Monitor Operation Counts",
        "The server provides new monitor operation counts for initiated and completed operation types.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.25",
        "Monitor Tracing Info",
        "The server provides monitor information for tracing options currently being used.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.26",
        "Null Base Subtree Search",
        "Server allows null based subtree search, which searches the entire DIT defined in the server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.27",
        "Proxy Authorization",
        "Server supports Proxy Authorization for a group of users.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.28",
        "TLS Capabilities",
        "Specifies that the server is actually capable of doing TLS.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.29",
        "Non-Blocking Replication",
        "The server is capable of ignoring some errors received from a consumer (replica) that would normally cause an update to be re-transmitted periodically until a successful result code was received.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.30",
        "Kerberos Capability",
        "Specifies that the server is capable of using Kerberos.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.31",
        "ibm-allMembers and ibm-allGroups operational attributes",
        "Indicates whether or not a backend supports searching on the ibm-allGroups and ibm-allMembers operational attributes.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.32",
        "FIPS mode for GSKit",
        "Enables the server to use the encryption algorithms from the ICC FIPS-certified library",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.35",
        "Modify DN (leaf move)",
        "Indicates if modify DN operation supports new superior for leaf entries. Note that this capability is implied by the pre-existing Modify DN (subtree move) capability. Applications should check for both capabilities.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.36",
        "Filtered Referrals",
        "The server supports limited filtered referrals.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.37",
        "Simplify resizing of attributes",
        "Allows customers to increase the maximum length of attributes through the schema modification facilities.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.38",
        "Global Administration Group",
        "Server supports the delegation of server administration to a group of administrators that are specified in the RDBM backend. Global Administrators do not have any authority to the configuration file or log files.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.39",
        "AES Encryption Option",
        "Server supports auditing of compare operations.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.40",
        "Auditing of Compare",
        "Server supports auditing of compare operations.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.41",
        "Log Management",
        "Identifies that this server supports log management.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.42",
        "Multi-threaded Replication",
        "Replication agreements can specify using multiple threads and connections to a consumer.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.43",
        "Supplier Replication Configuration",
        "Server configuration of suppliers for replication.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.44",
        "Using CN=IBMPOLICIES for Global Updates",
        "Server supports the replication of global updates using the replication topology in cn=IBMpolicies subtree.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.45",
        "Multihomed configuration support",
        "Server supports configuration on multiple IP addresses (multihomed).",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.46",
        "Multiple Directory Server Instances Architecture",
        "Server is designed to run with multiple directory server instances on the same machine.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.47",
        "Configuration Tool Auditing",
        "Server supports the auditing of the the configuration tools.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.48",
        "Audit consolidation configuration settings",
        "Indicates that audit log settings are available in the configuration file.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.49",
        "Proxy Server",
        "Describes whether this server is capable of acting as a proxy server or regular RDBM server. Optional Information.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.50",
        "LDAP Attribute Cache Auto Adjust",
        "Indicates if autonomic attribute cache is supported and enabled (deprecated in 6.3+).",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.51",
        "Replication conflict resolution max entry size",
        "Based on this number, a supplier may decide if an entry should be re-added to a target server in order to resolve a replication conflict.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.52",
        "LostAndFound log file",
        "Supports LostAndFound file for archiving replaced entries as a result of replication conflict resolution.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.53",
        "Password Policy Account Lockout",
        "Identifies that this server supports password policy Account Locked feature.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.54",
        "Password Policy Admin",
        "Identifies that this server supports Admin Password Policy.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.55",
        "IDS 6.0 SSL Fips processing mode",
        "Server supports SSL FIPS mode processing.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.56",
        "IDS 6.0 ibm-entrychecksumop",
        "Identifies that the 6.0 version of the ibm-entrychecksumop calculation was used on the server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.57",
        "LDAP Password Global Start Time",
        "Indicates that the server can support ibm-pwdPolicyStartTime attribute in the cn=pwdPolicy entry.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.58",
        "Audit Configuration Settings Consolidation",
        "Identifies that the audit configuration settings are now residing in the ibmslapd configuration file only.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.59",
        "CBE Log Format",
        "Indicates that Security Directory Server log management and conversion to event format is supported.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.60",
        "Encrypted Attribute Support",
        "Server supports encrypted attributes.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.61",
        "Proxy Monitor search",
        "Server supports special monitor searches intended for proxy server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.63",
        "SSHA Password Encrypt",
        "Server supports SSHA Password Encryption.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.64",
        "MD5 Password Encrypt",
        "Server supports MD5 Password Encryption.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.65",
        "Filter Replication",
        "The server feature designed to have only required entries and a subset of its attributes to be replicated.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.66",
        "Group Members Cache",
        "Server supports caching group members.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.67",
        "PKCS11 Support",
        "Server supports PKCS11 Encryption standard.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.68",
        "Server Admin Roles",
        "Server supports Server Administration roles.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.69",
        "Digest MD5 Support",
        "Server supports Digest MD5 Bind.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.70",
        "External Bind Support",
        "Server supports External Bind.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.71",
        "Persistent Search",
        "Server supports persistent search.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.72",
        "Admin Server Denial of Service Prevention",
        "Admin Server supports Denial of Service Prevention.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.73",
        "Admin server Enhanced Monitor Support",
        "Admin server supports 'cn=monitor', 'cn=connections,cn=monitor', and 'cn=workers,cn=monitor' searches.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.74",
        "Admin Server Support for Schema Searches",
        "Admin server supports searches on schema.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.76",
        "System Monitor Search",
        "Server supports cn=system,cn=monitor search.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.77",
        "Multiple Password Policies",
        "Server allows multiple password policy to be defined and used.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.78",
        "Passthrough Authentication",
        "Server supports pass through authentication feature.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.79",
        "Dynamic Updates of Replication Supplier Request",
        "Server supports dynamic updates of replication supplier information.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.81",
        "Audit Performance",
        "Server supports auditing of performance for operations.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.82",
        "No Emergency Thread Support",
        "Emergency Thread is not supported by server.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.83",
        "Enhanced Replication Group RI handling",
        "Enhanced Replication Group RI handling",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.84",
        "Reread the DB2 Password",
        "Server re-reads the DB2 password to identify any change in DB2 password specified in configuration.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.85",
        "Proxy Failback Based on Replication Queue",
        "Proxy Server will failback only when replication queue is below the threshold specified in configuration file.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.86",
        "Proxy Flow control",
        "Proxy server supports flow control algorithm.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.87",
        "Backup restore configuration capability",
        "Server supports configuring automatic backup and restore.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.88",
        "Password Policy Max Consecutive repeated characters",
        "Server supports restricting maximum consecutive repeated characters in password policy.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.89",
        "Virtual List View Support",
        "Server supports virtual list view control in searches.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.90",
        "Proxy Paged Search",
        "Proxy Server supports paged control in searches.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.92",
        "Tombstone Support",
        "Server supports tombstone for deleted entries.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.93",
        "Proxy Health Check outstanding limit",
        "Proxy supports identifying a hung server based on the configured outstanding health check requests.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.94",
        "Replication Finegrained timestamps",
        "Replication uses fine grained timestamp for resolving conflicts.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.96",
        "Distributed Dynamic group enabled",
        "Proxy Server Supports enabling/Disabling Distributed dynamic group configuration option.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.97",
        "Distributed group enabled",
        "Proxy Server Supports enabling/Disabling Distributed group configuration option.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.99",
        "SHA-2 support",
        "Indicates that this server supports SHA-2 family of algorithms (only applicable for servers with database backend).",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.101",
        "NIST SP800-131A Suite B",
        "Indicates that the server supports Suite B mode.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.102",
        "TLS 1.0 protocol",
        "Indicates that the server supports TLS v1.0 protocol.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.103",
        "TLS 1.1 protocol",
        "Indicates that the server supports TLS v1.1 protocol.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.104",
        "TLS 1.2 protocol",
        "Indicates that the server supports TLS v1.2 protocol.",
        "IBM Directory Server"),
    (
        "1.3.18.0.2.32.105",
        "Replication of security attributes",
        "Indicates that a read-only replica accepts the replication updates for password policy operational attributes.",
        "IBM Directory Server"),

    ############################################################################
    # Found on OpenDS/OpenDJ
    ############################################################################

    (
        "1.3.6.1.4.1.26027.1.6.1",
        "The password policy state extended operation",
        "",
        "OpenDS"),
    (
        "1.3.6.1.4.1.26027.1.6.2",
        "The get connection ID extended operation",
        "",
        "OpenDS"),
    (
        "1.3.6.1.4.1.26027.1.6.3",
        "The get symmetric key extended operation",
        "",
        "OpenDS"),
    (
        "1.3.6.1.4.1.26027.1.5.2",
        "Replication Repair Control",
        "",
        "OpenDS"),

    ################# Misc #################

    (
        "1.3.6.1.4.1.21008.108.63.1",
        "Session Tracking Control",
        "",
        "draft-wahl-ldap-session"
    ),

    ############################################################################
    # Found on ApacheDS
    ############################################################################

    (
        "1.3.6.1.4.1.18060.0.0.1",
        "CascadeControl",
        "",
        "ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.1",
        "LaunchDiagnosticUiRequest",
        "",
        "ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.2",
        "LaunchDiagnosticUiResponse",
        "",
        "ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.3",
        "GracefulShutdownRequest",
        "",
        "ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.4",
        "GracefulShutdownResponse",
        "",
        "ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.5",
        "GracefulDisconnect",
        "",
        "ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.6",
        "StoredProcedureRequest",
        "",
        "ApacheDS"),
    (
        "1.3.6.1.4.1.18060.0.1.7",
        "StoredProcedureResponse",
        "",
        "ApacheDS"),

    ################# Novell eDirectory 8.x #################
    # see http://developer.novell.com/documentation//ldapover/ldap_enu/data/a6ik7oi.html

    (
        "2.16.840.1.113719.1.27.103.7",
        "GroupingControl",
        "groups a set of write operations with a cookie received with CreateGroupingRequest",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.1",
        "ndsToLdapResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.2",
        "ndsToLdapRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.3",
        "createNamingContextRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.4",
        "createNamingContextResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.5",
        "mergeNamingContextRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.6",
        "mergeNamingContextResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.7",
        "addReplicaRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.8",
        "addReplicaResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.9",
        "refreshLDAPServerRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.10",
        "refreshLDAPServerResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.11",
        "removeReplicaRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.12",
        "removeReplicaResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.13",
        "namingContextEntryCountRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.14",
        "namingContextEntryCountResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.15",
        "changeReplicaTypeRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.16",
        "changeReplicaTypeResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.17",
        "getReplicaInfoRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.18",
        "getReplicaInfoResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.19",
        "listReplicaRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.20",
        "listReplicaResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.21",
        "receiveAllUpdatesRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.22",
        "receiveAllUpdatesResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.23",
        "sendAllUpdatesRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.24",
        "sendAllUpdatesResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.25",
        "requestNamingContextSyncRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.26",
        "requestNamingContextSyncResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.27",
        "requestSchemaSyncRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.28",
        "requestSchemaSyncResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.29",
        "abortNamingContextOperationRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.30",
        "abortNamingContextOperationResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.31",
        "getContextIdentityNameRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.32",
        "getContextIdentityNameResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.33",
        "getEffectivePrivilegesRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.34",
        "getEffectivePrivilegesResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.35",
        "SetReplicationFilterRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.37",
        "getReplicationFilterRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.39",
        "createOrphanPartitionrequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.41",
        "removeOrphanPartitionRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.43",
        "triggerBKLinkerRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.45",
        "triggerDRLProcessRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.47",
        "triggerJanitorRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.49",
        "triggerLimberRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.51",
        "triggerSkulkerRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.53",
        "triggerSchemaSyncRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.55",
        "triggerPartitionPurgeRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.79",
        "EventMonitorRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.84",
        "filteredEventMonitorRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.103.1",
        "createGroupingRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.103.2",
        "endGroupingRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.1",
        "Put Login Configuration",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.3",
        "Get Login Configuration",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.5",
        "Delete Login Configuration",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.7",
        "Put Login Secret",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.9",
        "Delete Login Secret",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.11",
        "Set Universal Password",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.13",
        "Get Universal Password",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.15",
        "Delete Universal Password",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.17",
        "Check password against password policy",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.2",
        "SSLDAP_GET_SERVICE_INFO_REPLY",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.4",
        "SSLDAP_READ_SECRET_REPLY",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.6",
        "SSLDAP_WRITE_SECRET_REPLY",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.8",
        "SSLDAP_ADD_SECRET_ID_REPLY",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.10",
        "SSLDAP_REMOVE_SECRET_REPLY",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.12",
        "SSLDAP_REMOVE_SECRET_STORE_REPLY",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.14",
        "SSLDAP_ENUMERATE_SECRET_IDS_REPLY",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.16",
        "SSLDAP_UNLOCK_SECRETS_REPLY",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.148.100.18",
        "SSLDAP_SET_EP_MASTER_PASSWORD_REPLY",
        "",
        "Novell eDirectory (NDS)"),

    # LDAP Extensions Used by the Novell Import Convert Export Utility
    # LDAP Bulk Update Replication Protocol (LBURP)

    (
        "2.16.840.1.113719.1.142.100.1",
        "startFramedProtocolRequest",
        "",
        "Novell eDirectory (NDS): draft-ietf-ldup-framing"),
    (
        "2.16.840.1.113719.1.142.100.2",
        "startFramedProtocolResponse",
        "",
        "Novell eDirectory (NDS): draft-ietf-ldup-framing"),
    (
        "2.16.840.1.113719.1.142.100.3",
        "ReplicationUpdate",
        "",
        "draft-ietf-ldup-protocol"),
    (
        "2.16.840.1.113719.1.142.100.4",
        "endFramedProtocolRequest",
        "",
        "Novell eDirectory (NDS): draft-ietf-ldup-framing"),
    (
        "2.16.840.1.113719.1.142.100.5",
        "endFramedProtocolResponse",
        "",
        "Novell eDirectory (NDS): draft-ietf-ldup-framing"),
    (
        "2.16.840.1.113719.1.142.100.6",
        "lburpOperationRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.142.100.7",
        "lburpOperationResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.96",
        "LDAPBackupRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.97",
        "LDAPBackupResponse",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.98",
        "LDAPRestoreRequest",
        "",
        "Novell eDirectory (NDS)"),

    (
        "2.16.840.1.113719.1.27.100.101",
        "DNStoX500DNRequest",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.27.100.102",
        "DNStoX500DNResponse",
        "",
        "Novell eDirectory (NDS)"),


    (
        "2.16.840.1.113719.1.39.42.100.1",
        "NMAS Put Login Configuration Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.3",
        "NMAS Get Login Configuration Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.5",
        "NMAS Delete Login Configuration Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.7",
        "NMAS Put Login Secret Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.9",
        "NMAS Delete Login Secret Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.11",
        "NMAS Set Password Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.12",
        "NMAS Set Password Response",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.13",
        "NMAS Get Password Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.14",
        "NMAS Get Password Response",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.15",
        "NMAS Delete Password Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.17",
        "NMAS Password Policy Check Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.19",
        "NMAS Get Password Policy Info Request",
        "",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.21",
        "NMAS Change Password Request",
        "Change (Universal?) Password",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.23",
        "NMAS GAMS Request",
        "NMAS Graded Authentication management",
        "Novell eDirectory (NDS)"),
    (
        "2.16.840.1.113719.1.39.42.100.25",
        "NMAS management (new with NMAS 3.1.0)",
        "",
        "Novell eDirectory (NDS)"),

    # FreeIPA
    (
        "2.16.840.1.113730.3.8.10.6",
        "OTPSyncRequest",
        "OTP token synchronization request control",
        "FreeIPA"),

    # OpenDJ/OpenAM
    (
        "1.3.6.1.4.1.36733.2.1.5.1",
        "TransactionID request control",
        "",
        "OpenDJ/OpenAM"),

)


def build_reg():
    """
    build the globally readable OID dictionary
    """
    reg = {}
    for oid, name, desc, ref in OID_LIST:
        assert isinstance(oid, str), TypeError("Wrong type for 'oid' for OID %r" % (oid))
        assert isinstance(name, str), TypeError("Wrong type for 'name' for OID %r" % (oid))
        assert isinstance(desc, str), TypeError("Wrong type for 'description' for OID %r" % (oid))
        assert isinstance(ref, str), TypeError("Wrong type for 'reference' for OID %r" % (oid))
        if oid in reg:
            logger.warning(
                'Double OID %r in web2ldap.ldaputil.oidreg.OID_LIST: %r vs. %r',
                oid,
                name,
                reg[oid][0],
            )
        else:
            reg[oid] = (name, desc, ref)
    logger.debug('Added %d items to web2ldap.ldaputil.oidreg.reg', len(reg))
    return reg

OID_REG = build_reg()
