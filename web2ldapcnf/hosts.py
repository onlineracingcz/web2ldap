# -*- coding: ascii -*-
"""
web2ldapcnf.hosts - Configuration options for specific LDAP servers

See documentation for details:
https://www.web2ldap.de/web2ldapcnf_hosts.html
https://www.web2ldap.de/usability.html

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>
"""

# Leave these import lines alone
import os
import ldap0

from web2ldap import ETC_DIR, TEMPLATES_DIR, Web2LDAPConfig

########################################################################
# List of all LDAP hosts to use. These hosts will appear in the
# default select list of the login form.
# A list containing only one host results in a normal input field
# with the host set as default.
########################################################################

ldap_uri_list = [
    (
        (
            'ldaps://demo.ae-dir.com/ou=ae-dir????'
            'bindname=aead,X-BINDPW=CorrectHorseBatteryStaple'
        ),
        '\xC6-DIR demo role \xC6 admin',
    ),
    (
        (
            'ldap://ipa.demo1.freeipa.org/dc=demo1,dc=freeipa,dc=org??one??'
            'bindname=uid%3Dadmin%2Ccn%3Dusers%2Ccn%3Daccounts%2Cdc%3Ddemo1%2Cdc%3Dfreeipa%2Cdc%3Dorg,X-BINDPW=Secret123'
        ),
        'FreeIPA demo as admin',
    ),
    (
        'ldaps://db.debian.org/dc=debian,dc=org??one',
        'debian.org Developers LDAP Search'
    ),
    (
        'ldap://x500.bund.de/o=Bund,c=DE??one',
        'X.500 Directory Informationsverbund Berlin-Bonn'
    ),
    (
        'ldap://pks-ldap.telesec.de/c=DE',
        'T-TeleSec PKS',
    ),
    (
        'ldap://ldap.nrca-ds.de/dc=ldap,dc=nrca-ds,dc=de??one',
        u"Qualified certificates of german BNetzA",
    ),
    (
        'ldap://ldap.itd.umich.edu',
        'MCommunity Directory at University of Michigan',
    ),
    (
        'ldap://ldap.swissdigicert.ch/dc%3Dswissdigicert%2Cdc%3Dch??one?',
        'SwissDigiCert',
    ),
    (
        'ldap://ldap.a-trust.at/c=AT??one?',
        'A-Trust PKI Verzeichnisdienst',
    ),
    (
        'ldap://ldap1.pca.dfn.de/ou%3DDFN-PKI%2Co%3DDFN-Verein%2Cc%3Dde??one',
        'DFN-PKI',
    ),
    (
        'ldap://ldap.sbca.telesec.de/c=de??one',
        'T-Systems Shared Business',
    ),
    (
        'ldap://ldap.crl.esecure.datev.de/??one',
        'DATEV',
    ),
    (
        'ldap://directory.swisssign.net/o=SwissSign,c=CH??one',
        'SwissSign AG',
    ),
    (
        (
            'ldap://ldap.forumsys.com/dc=example,dc=com????'
            'bindname=cn%3Dread-only-admin%2Cdc%3Dexample%2Cdc%3Dcom,X-BINDPW=password'
        ),
        'Access ldap.forumsys.com as user "read-only-admin"',
    ),
]

# Set to True if LDAP access should be restricted to the LDAP servers
# defined in ldap_uri_list
restricted_ldap_uri_list = False

########################################################################
# Init some re-usable preset configuration instances
# which are registered in ldap_def below
########################################################################

#---------------------------------------------------------------------------
# Presets for MS Active Directory
#---------------------------------------------------------------------------

MSAD_CONFIG = Web2LDAPConfig(
    description='MS Active Directory',
    searchform_template={
        '_': os.path.join(TEMPLATES_DIR, 'msad', 'searchform.html'),
    },
    boundas_template={
        'user':r'<strong>%(cn)s</strong> (%(sAMAccountName)s)',
        'computer':r'<strong>%(cn)s</strong> (%(sAMAccountName)s)',
    },
    # anonymous search normally not allowed for MS AD
    binddn_mapping='',
    requested_attrs=(
        'structuralObjectClass', 'subschemaSubentry',
        # counters
        'hasSubordinates',
        # Dynamic Entries (see RFC 2589)
        'entryTTL',
        # MS Active Directory
        'nTSecurityDescriptor',
        'tokenGroups', 'tokenGroupsGlobalAndUniversal', 'tokenGroupsNoGCAcceptable',
        'mS-DS-CreatorSID', 'primaryGroupToken', 'canonicalName', 'fromEntry',
        'sDRightsEffective', 'msDS-Approx-Immed-Subordinates', 'msDS-KeyVersionNumber',
        'msDS-ReplAttributeMetaData',
        'lastLogonTimestamp', 'lockoutTime',
        'allowedAttributes', 'allowedAttributesEffective',
        'allowedChildClasses', 'allowedChildClassesEffective',
    ),
    modify_constant_attrs=(
        'uSNChanged', 'uSNCreated', 'whenChanged', 'whenCreated',
    ),
    addform_entry_templates={
        'User': os.path.join(TEMPLATES_DIR, 'msad', 'add_user.ldif'),
        'Computer': os.path.join(TEMPLATES_DIR, 'msad', 'add_computer.ldif'),
        'Organizational unit (OU)': os.path.join(TEMPLATES_DIR, 'add_orgunit.ldif'),
        'Group': os.path.join(TEMPLATES_DIR, 'add_group.ldif'),
        'Container': os.path.join(TEMPLATES_DIR, 'msad', 'add_container.ldif'),
    },
    groupadm_defs={
        'group': ('member', None),
    },
)

#---------------------------------------------------------------------------
# Presets for OpenLDAP's accesslog DB
#---------------------------------------------------------------------------

OPENLDAP_ACCESSLOG_CONFIG = Web2LDAPConfig(
    description='OpenLDAP accesslog',
    search_tdtemplate={
        'auditSearch':(
            '<strong>%(reqType)s</strong> %(reqStart)s session %(reqSession)s<br>'
            '&rArr; %(reqResult)s: %(reqMessage)s<br>Search %(reqScope)s: %(reqDN)s<br>%(reqFilter)s'
        ),
        'auditBind':(
            '<strong>%(reqType)s</strong> %(reqStart)s session %(reqSession)s<br>'
            '&rArr; %(reqResult)s: %(reqMessage)s: %(reqSession)s<br>%(reqDN)s'
        ),
        'auditAdd':(
            '<strong>%(reqType)s</strong> %(reqStart)s session %(reqSession)s<br>'
            '&rArr; %(reqResult)s: %(reqMessage)s<br>Entry %(reqDN)s added<br>by %(reqAuthzID)s'
        ),
        'auditModify':(
            '<strong>%(reqType)s</strong> %(reqStart)s session %(reqSession)s<br>'
            '&rArr; %(reqResult)s: %(reqMessage)s<br>Entry %(reqDN)s modified<br>by %(reqAuthzID)s'
        ),
        'auditModRDN':(
            '<strong>%(reqType)s</strong> %(reqStart)s session %(reqSession)s<br>'
            '&rArr; %(reqResult)s: %(reqMessage)s<br>Entry %(reqDN)s renamed to'
            '%(reqNewRDN)s,%(reqNewSuperior)s<br>by %(reqAuthzID)s'
        ),
        'auditObject':(
            '<strong>%(reqType)s</strong> %(reqStart)s session %(reqSession)s<br>'
            '&rArr; %(reqResult)s: %(reqMessage)s<br>by %(reqAuthzID)s'
        ),
        'auditDelete':(
            '<strong>%(reqType)s</strong> %(reqStart)s session %(reqSession)s<br>'
            '&rArr; %(reqResult)s: %(reqMessage)s<br>Entry %(reqDN)s deleted<br>by %(reqAuthzID)s'
        ),
        'auditAbandon':(
            '<strong>%(reqType)s</strong> %(reqStart)s session %(reqSession)s<br>'
            '&rArr; %(reqResult)s: %(reqMessage)s<br>Abandoned %(reqId)s by %(reqAuthzID)s'
        ),
    },
    searchform_template={
        '_': os.path.join(TEMPLATES_DIR, 'searchform_accesslog.html'),
    },
    search_attrs=(
        'objectClass',
        'reqAuthzID', 'reqDN', 'reqEnd', 'reqEntryUUID', 'reqMod', 'reqOld',
        'reqResult', 'reqSession', 'reqStart', 'reqType',
    ),
    read_template={
        'auditAdd': os.path.join(TEMPLATES_DIR, 'openldap', 'read_auditAdd.html'),
        'auditModify': os.path.join(TEMPLATES_DIR, 'openldap', 'read_auditAdd.html'),
        'auditModRDN': os.path.join(TEMPLATES_DIR, 'openldap', 'read_auditModRDN.html'),
        'auditDelete': os.path.join(TEMPLATES_DIR, 'openldap', 'read_auditDelete.html'),
    },
)

#---------------------------------------------------------------------------
# Presets for changelog database
#---------------------------------------------------------------------------

CHANGELOG_CONFIG = Web2LDAPConfig(
    description='changelog',
    search_tdtemplate={
        'changelogentry':(
            'No. %(changenumber)s at %(changetime)s<br>'
            '%(changetype)s %(targetdn)s (%(targetentryuuid)s)<br>'
            'by %(changeInitiatorsName)s'
        ),
    },
    searchform_template={
        '_': os.path.join(TEMPLATES_DIR, 'searchform_changelog.html'),
    },
    search_attrs=(
        'changeType', 'targetDN', 'targetEntryUUID', 'changeTime',
        'changeLogCookie', 'replicaIdentifier', 'replicationCSN', 'changeInitiatorsName',
    ),
    read_template={
        'changeLogEntry': os.path.join(TEMPLATES_DIR, 'read_changeLogEntry.html'),
    },
)

#---------------------------------------------------------------------------
# Presets for OpenLDAP's cn=monitor
#---------------------------------------------------------------------------

OPENLDAP_MONITOR_CONFIG = Web2LDAPConfig(
    # Important workaround for OpenLDAP bug ITS#7053 !!!
    search_resultsperpage=0,
    search_tdtemplate={
        # for OpenLDAP
        'monitorOperation':r'%(cn)s operations: %(monitorOpCompleted)s of %(monitorOpInitiated)s completed',
        'monitoredObject':(
            '%(cn)s: %(monitoredInfo)s<br>'
            '%(monitorTimestamp)s %(namingContexts)s %(labeledURI)s<br>'
            '%(seeAlso)s'
        ),
        'monitorContainer':r'%(cn)s - %(description)s',
        'monitorCounterObject':r'%(cn)s: %(monitorCounter)s',
        'monitorConnection':(
            'Connection %(monitorConnectionNumber)s (LDAPv%(monitorConnectionProtocol)s):<br>'
            '%(monitorConnectionPeerAddress)s &raquo; %(monitorConnectionListener)s<br>'
            '%(monitorConnectionAuthzDN)s<br>'
            '(ops r: %(monitorConnectionOpsReceived)s, e: %(monitorConnectionOpsExecuting)s, p: %(monitorConnectionOpsPending)s, c: %(monitorConnectionOpsCompleted)s)'
        ),
        # new in OpenLDAP 2.5
        'olmSyncReplInstance':(
            '%(cn)s - %(olmSRSyncPhase)s<br>'
            'Providers: %(olmSRProviderURIList)s %(olmSRConnection)s<br>'
            'Last connect: %(olmSRLastConnect)s<br>'
            'Last contact: %(olmSRLastContact)s<br>'
            'Last cookie received: %(olmSRLastCookieRcvd)s<br>'
            'Last cookie sent: %(olmSRLastCookieSent)s<br>'
            'Next connect: %(olmSRNextConnect)s<br>'
        ),
    },
    read_template={
        # for OpenLDAP
        'monitorConnection': os.path.join(TEMPLATES_DIR, 'read_monitorConnection.html'),
        # new in OpenLDAP 2.5
        'olmSyncReplInstance': os.path.join(TEMPLATES_DIR, 'read_olmSyncReplInstance.html'),
    },
)

#---------------------------------------------------------------------------
# Presets for cn=config supporting various vendors
#---------------------------------------------------------------------------

# For dynamic configuration via cn=config
CN_CONFIG = Web2LDAPConfig(
    description=u"Configuration backend",
    search_tdtemplate={
        # for OpenLDAP
        'olcModuleList':r'Modules from %(olcModulePath)s',
        'olcDatabaseConfig':r'Database <em>%(olcDatabase)s</em> suffix %(olcSuffix)s',
        'olcSchemaConfig':r'Schema <em>%(cn)s</em>',
        'olcOverlayConfig':r'Overlay <em>%(olcOverlay)s</em>',
        # for OpenDS/OpenDJ
        'ds-cfg-backend':r'Backend <em>%(ds-cfg-backend-id)s</em>, suffix <em>%(ds-cfg-base-dn)s</em><br>Class: %(ds-cfg-java-class)s',
        'ds-cfg-local-db-index':r'Index for <em>%(ds-cfg-attribute)s</em>: <em>%(ds-cfg-index-type)s</em>',
        'ds-cfg-replication-server':(
            'Replication server-id <em>%(ds-cfg-replication-server-id)s</em>:<br>'
            'Replication server(s): %(ds-cfg-replication-server)s'
        ),
        'ds-cfg-replication-domain':(
            'Replication domain <em>%(cn)s</em>:<br>'
            'Server-ID: %(ds-cfg-server-id)s<br>'
            'Base-DN: %(ds-cfg-base-dn)s<br>'
            'Replication server(s): %(ds-cfg-replication-server)s'
        ),
    },
    read_template={
        # for OpenLDAP
        'olcGlobal': os.path.join(TEMPLATES_DIR, 'openldap', 'read_olcGlobal.html'),
        'olcHdbConfig': os.path.join(TEMPLATES_DIR, 'openldap', 'read_olcHdbConfig.html'),
        'olcMdbConfig': os.path.join(TEMPLATES_DIR, 'openldap', 'read_olcMdbConfig.html'),
    },
    input_template={
        # for OpenLDAP
        'olcGlobal': os.path.join(TEMPLATES_DIR, 'openldap', 'inputform_olcGlobal.html'),
        'olcHdbConfig': os.path.join(TEMPLATES_DIR, 'openldap', 'inputform_olcHdbConfig.html'),
        'olcMdbConfig': os.path.join(TEMPLATES_DIR, 'openldap', 'inputform_olcMdbConfig.html'),
    },
    # HTML template strings used to display the superior entry
    # in the input form when adding/modifying entries
    inputform_supentrytemplate={
        # for OpenLDAP
        'olcDatabaseConfig':(
            '<table>'
            '<tr><td>Database name:</td><td>%(olcDatabase)s</td></tr>'
            '<tr><td>Suffix:</td><td>%(olcSuffix)s</td></tr>'
            '</table>'
        )
    },
    addform_entry_templates={
        # for OpenLDAP
        'Modules': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcModuleList.ldif'),
        'Database - Address book (back-hdb)': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcHdbConfig_AddressBook.ldif'),
        'Database - Unix Users (back-hdb)': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcHdbConfig_UnixUsers.ldif'),
        'Database - Accesslog (back-hdb)': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcHdbConfig_accesslog.ldif'),
        'Database - LDAP-Proxy (back-ldap)': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcLdapConfig.ldif'),
        'Database - back-mdb': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcMdbConfig.ldif'),
        'Overlay - Syncrepl-Provider (slapo-syncprov)': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcHdbConfig_accesslog.ldif'),
        'Overlay - Accesslog (slapo-accesslog)': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcHdbConfig_accesslog.ldif'),
        'Schema config': os.path.join(TEMPLATES_DIR, 'openldap', 'add_olcSchemaConfig.ldif'),
    },
)

#---------------------------------------------------------------------------
# Presets for AE-DIR
#---------------------------------------------------------------------------

AE_DIR_CONFIG = Web2LDAPConfig(
    description='\xC6-DIR',
    top_template=os.path.join(TEMPLATES_DIR, 'ae-dir', 'top.html'),
    binddn_mapping='ldap:///uid={user},_??base',
    boundas_template={
        'aeUser':r'<span title="%(displayName)s: %(description)s">%(uid)s: %(description)s</span>',
    },
    session_track_control=True,
    supplement_schema=os.path.join(ETC_DIR, 'ae-suppl-schema.ldif'),
    modify_constant_attrs=(
        # Mostly OpenLDAP
        'entryCSN', 'entryDN', 'entryUUID',
        # see RFC
        'createTimestamp', 'modifyTimestamp', 'creatorsName', 'modifiersName',
    ),
    login_template=os.path.join(TEMPLATES_DIR, 'ae-dir', 'login.html'),
    addform_parent_attrs=('entryUUID',),
    search_attrs=(
        'aeDept',
        'aeDevicePort',
        'aeDeviceSlot',
        'aeDisplayNameGroups',
        'aeFqdn',
        'aeHost',
        'aeHwSerialNumber',
        'aeLocation',
        'aeLoginGroups',
        'aeLogStoreGroups',
        'aeLogStorePeriod',
        'aeNotAfter',
        'aeNotBefore',
        'aeNwDevice',
        'aePasswordAdmins',
        'aePerson',
        'aeProxyFor',
        'aeRemoteHost',
        'aeRequires',
        'aeSetupGroups',
        'aeSourceUri',
        'aeSrvGroup',
        'aeStatus',
        'aeStockId',
        'aeTag',
        'aeTicketId',
        'aeVisibleGroups',
        'aeVisibleSudoers',
        'aeZoneAdmins',
        'aeZoneAuditors'
        'authTimestamp',
        'cn',
        'createTimestamp',
        'creatorsName',
        'departmentNumber',
        'description',
        'displayName',
        'distinguishedName',
        'employeeNumber',
        'employeeType',
        'entryDN',
        'entryUUID',
        'facsimileTelephoneNumber',
        'gidNumber',
        'givenName',
        'hasSubordinates',
        'homeDirectory',
        'homePhone',
        'host',
        'ipHostNumber',
        'ipNetmaskNumber',
        'ipNetworkNumber',
        'l',
        'labeledURI',
        'loginShell',
        'macAddress',
        'mail',
        'mailLocalAddress',
        'manager',
        'member',
        'memberOf',
        'memberURL',
        'mobile',
        'modifiersName',
        'modifyTimestamp',
        'msPwdResetAdminPw',
        'msPwdResetEnabled',
        'msPwdResetExpirationTime',
        'msPwdResetPasswordHash',
        'msPwdResetTimestamp',
        'name',
        'o',
        'oathFailureCount',
        'oathHMACAlgorithm',
        'oathHOTPCounter',
        'oathHOTPParams',
        'oathHOTPToken',
        'oathLastFailure',
        'oathLastLogin',
        'oathSecretTime',
        'oathThrottleLimit',
        'oathToken',
        'oathTokenIdentifier',
        'oathTokenSerialNumber',
        'oathTOTPParams',
        'oathTOTPToken',
        'objectClass',
        'ou',
        'personalTitle',
        'postalAddress',
        'postalCode',
        'pwdAccountLockedTime',
        'pwdAllowUserChange',
        'pwdAttribute',
        'pwdChangedTime',
        'pwdFailureTime',
        'pwdHistory',
        'pwdLockout',
        'pwdMustChange',
        'pwdPolicySubentry',
        'pwdReset',
        'seeAlso',
        'serialNumber',
        'sn',
        'sshPublicKey',
        'street',
        'structuralObjectClass',
        'sudoCommand',
        'sudoHost',
        'sudoNotAfter',
        'sudoNotBefore',
        'sudoOption',
        'sudoOrder',
        'sudoRunAs',
        'sudoRunAsGroup',
        'sudoRunAsUser',
        'sudoUser',
        'telephoneNumber',
        'title',
        'uid',
        'uidNumber',
        'uniqueIdentifier',
        'userPassword',
    ),
    searchform_search_root_url='ldap:///ou=ae-dir??one?(|(objectClass=aeZone))',
    searchform_template={
        '_': os.path.join(TEMPLATES_DIR, 'ae-dir', 'searchform_aedir.html'),
    },
    search_tdtemplate={
        'aeUser':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              '%(displayName)s / %(description)s<br>'
              '<dl>'
                '<dt>Member of:</dt>'
                '<dd>%(memberOf)s</dd>'
              '</dl>'
            '</div>'
        ),
        'aeDept':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              '%(ou)s (%(departmentNumber)s)'
            '</div>'
        ),
        'aePerson':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              '%(displayName)s &lt;%(mail)s&gt;'
            '</div>'
        ),
        'aeGroup':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'User group %(cn)s (%(gidNumber)s):<br>'
              '%(description)s'
            '</div>'
        ),
        'aeMailGroup':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Mail group %(cn)s &lt;%(mail)s&gt;<br>'
              '%(description)s'
            '</div>'
        ),
        'aeSrvGroup':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Server group %(cn)s:<br>'
              '%(description)s'
            '</div>'
        ),
        'aeService':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Service account %(uid)s:<br>'
              '%(description)s'
              '<dl>'
                '<dt>Member of:</dt>'
                '<dd>%(memberOf)s</dd>'
              '</dl>'
            '</div>'
        ),
        'aeHost':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Server %(cn)s: %(host)s<br>'
              '%(description)s'
            '</div>'
        ),
        'aeNwDevice':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              '%(aeFqdn)s:<br>'
              'inet addr:%(ipHostNumber)s<br>'
              'HWaddr: %(macAddress)s'
            '</div>'
        ),
        'aeSudoRule':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Sudo rule %(cn)s:<br>'
              '%(description)s'
            '</div>'
        ),
        'aeTag':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Tag %(cn)s: %(description)s'
            '</div>'
        ),
        'aeZone':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Zone %(cn)s: %(description)s'
            '</div>'
        ),
        'aeRoot':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Org unit %(ou)s:<br>'
              '%(description)s'
            '</div>'
        ),
        'aeAuthcToken':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Authentication token %(displayName)s'
            '</div>'
        ),
        'aePolicy':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Policy %(cn)s: %(description)s'
            '</div>'
        ),
        'aeContact':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Contact %(cn)s: %(description)s'
              '<dl>'
                '<dt>Member of:</dt>'
                '<dd>%(memberOf)s</dd>'
              '</dl>'
            '</div>'
        ),
        'aeLocation':(
            '<div class="aestatus%(aeStatus)s">'
              '<var>%(entryDN)s</var><br>'
              'Location %(displayName)s'
            '</div>'
        ),
    },
    read_template={
        'msPwdResetObject': os.path.join(TEMPLATES_DIR, 'read_msPwdResetObject.html'),
        'posixAccount': os.path.join(TEMPLATES_DIR, 'read_posixAccount.html'),
        'aePolicy': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aePolicy.html'),
        'pwdPolicy': os.path.join(TEMPLATES_DIR, 'read_pwdPolicy.html'),
        'msPwdResetPolicy': os.path.join(TEMPLATES_DIR, 'read_msPwdResetPolicy.html'),
        'aeRoot': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeRoot.html'),
        'aeGroup': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeGroup.html'),
        'aeMailGroup': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeMailGroup.html'),
        'aeDept': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeDept.html'),
        'aeLocation': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeLocation.html'),
        'aePerson': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aePerson.html'),
        'aeHost': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeHost.html'),
        'aeService': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeService.html'),
        'aeSrvGroup': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeSrvGroup.html'),
        'aeSSHAccount': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeSSHAccount.html'),
        'aeSudoRule': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeSudoRule.html'),
        'aeTag': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeTag.html'),
        'aeUser': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeUser.html'),
        'aeAuthcToken': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeAuthcToken.html'),
        'aeZone': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeZone.html'),
        'aeContact': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aeContact.html'),
        'aePosixIdRanges': os.path.join(TEMPLATES_DIR, 'ae-dir', 'read_aePosixIdRanges.html'),
        'mailboxRelatedObject': os.path.join(TEMPLATES_DIR, 'read_mailboxRelatedObject.html'),
        'namedObject': os.path.join(TEMPLATES_DIR, 'read_namedObject.html'),
        'namedPolicy': os.path.join(TEMPLATES_DIR, 'read_namedPolicy.html'),
        'inetLocalMailRecipient': os.path.join(TEMPLATES_DIR, 'read_inetLocalMailRecipient.html'),
        'oathHOTPUser': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathHOTPUser.html'),
        'oathTOTPUser': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathTOTPUser.html'),
        'oathHOTPToken': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathHOTPToken.html'),
        'oathTOTPToken': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathTOTPToken.html'),
        'oathParams': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathParams.html'),
        'oathHOTPParams': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathHOTPParams.html'),
        'oathTOTPParams': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathTOTPParams.html'),
    },
    input_template={
        'msPwdResetObject': os.path.join(TEMPLATES_DIR, 'inputform_msPwdResetObject.html'),
        'posixAccount': os.path.join(TEMPLATES_DIR, 'inputform_posixAccount.html'),
        'aePolicy': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aePolicy.html'),
        'pwdPolicy': os.path.join(TEMPLATES_DIR, 'inputform_pwdPolicy.html'),
        'msPwdResetPolicy': os.path.join(TEMPLATES_DIR, 'inputform_msPwdResetPolicy.html'),
        'aeDept': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeDept.html'),
        'aeLocation': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeLocation.html'),
        'aeGroup': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeGroup.html'),
        'aeMailGroup': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeMailGroup.html'),
        'aeHost': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeHost.html'),
        'aeService': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeService.html'),
        'aeSrvGroup': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeSrvGroup.html'),
        'aeSSHAccount': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeSSHAccount.html'),
        'aeSudoRule': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeSudoRule.html'),
        'aeTag': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeTag.html'),
        'aeUser': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeUser.html'),
        'aeAuthcToken': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeAuthcToken.html'),
        'aeZone': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeZone.html'),
        'aePerson': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aePerson.html'),
        'aeContact': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aeContact.html'),
        'aePosixIdRanges': os.path.join(TEMPLATES_DIR, 'ae-dir', 'inputform_aePosixIdRanges.html'),
        'mailboxRelatedObject': os.path.join(TEMPLATES_DIR, 'inputform_mailboxRelatedObject.html'),
        'namedObject': os.path.join(TEMPLATES_DIR, 'inputform_namedObject.html'),
        'namedPolicy': os.path.join(TEMPLATES_DIR, 'inputform_namedPolicy.html'),
        'inetLocalMailRecipient': os.path.join(TEMPLATES_DIR, 'inputform_inetLocalMailRecipient.html'),
        'oathHOTPUser': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathHOTPUser.html'),
        'oathTOTPUser': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathTOTPUser.html'),
        'oathHOTPToken': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathHOTPToken.html'),
        'oathTOTPToken': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathTOTPToken.html'),
        'oathParams': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathParams.html'),
        'oathHOTPParams': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathHOTPParams.html'),
        'oathTOTPParams': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathTOTPParams.html'),
    },
    inputform_supentrytemplate={
        'aeRoot':r'%(description)s (aeRoot)',
        'aeZone':r'Zone <strong>%(cn)s</strong>: %(description)s',
        'aeSrvGroup':r'Service group <strong>%(cn)s</strong>: %(description)s',
        'aeHost':r'Host/server: <strong>%(host)s</strong>',
    },
    addform_entry_templates={
        '\xC6-DIR tag': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeTag.ldif'),
        '\xC6-DIR user group': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeGroup.ldif'),
        '\xC6-DIR mail group': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeMailGroup.ldif'),
        '\xC6-DIR primary user account': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeUser_inetLocalMailRecipient.ldif'),
        '\xC6-DIR personal user account': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeUser.ldif'),
        '\xC6-DIR OATH-HOTP token': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_oath_hotp_token.ldif'),
        #'\xC6-DIR OATH-TOTP token': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_oath_totp_token.ldif'),
        '\xC6-DIR password policy': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_pwdPolicy.ldif'),
        '\xC6-DIR OATH-HOTP parameters': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_oathHOTPParams.ldif'),
        '\xC6-DIR person': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aePerson.ldif'),
        '\xC6-DIR contact': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeContact.ldif'),
        '\xC6-DIR department': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeDept.ldif'),
        '\xC6-DIR location': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeLocation.ldif'),
        '\xC6-DIR network device': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeNwDevice.ldif'),
        '\xC6-DIR server/service group': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeSrvGroup.ldif'),
        '\xC6-DIR server/host': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeHost.ldif'),
        '\xC6-DIR service/tool account (POSIX)': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeService_posixAccount.ldif'),
        '\xC6-DIR service/tool account': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeService.ldif'),
        '\xC6-DIR zone': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeZone.ldif'),
        '\xC6-DIR zone admins group': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeGroup_zone-admins.ldif'),
        '\xC6-DIR zone auditors group': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeGroup_zone-auditors.ldif'),
        '\xC6-DIR replica account': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_slapd-replica.ldif'),
        '\xC6-DIR login proxy': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_login-proxy.ldif'),
        '\xC6-DIR sudo su - root': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeSudoRule_su_root.ldif'),
        '\xC6-DIR sudoers entry': os.path.join(TEMPLATES_DIR, 'ae-dir', 'add_aeSudoRule.ldif'),
    },
    passwd_template=os.path.join(TEMPLATES_DIR, 'ae-dir', 'passwd.html'),
    passwd_hashtypes=('ssha', ''),
    passwd_genchars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    passwd_genlength=24,
    groupadm_filterstr_template=r'(&(|(objectClass=aeGroup)(objectClass=aeMailGroup))(aeStatus=0)(!(memberURL=*))(|%s))',
    groupadm_optgroup_bounds=(-2, -1),
    groupadm_defs={
        'groupOfEntries': ('member', None, True),
        'posixGroup': ('memberUid', 'uid', False),
        'nisMailAlias': ('rfc822MailMember', 'mail', False),
    },
    read_tablemaxcount={
        'member':40,
        'memberUid':40,
        'memberOf':30,
        'allowedAttributes':2,
        'allowedAttributesEffective':2,
        'allowedChildClasses':2,
        'allowedChildClassesEffective':2,
    },
    requested_attrs=(
        # Proxy Authz attributes
        'authzTo', 'authzFrom',
        # password policy attributes
        'pwdPolicySubentry',
    ),
    rename_supsearchurl={
        'Search for zone (aeZone)': 'ldap:///_??one?(objectClass=aeZone)',
        'Search for server/service group (aeSrvGroup)': 'ldap:///_??sub?(objectClass=aeSrvGroup)',
    },
    # Use delold: 1 with MODRDN requests when doing bulk renaming
    bulkmod_delold=True,
)

# Overall default values.
# There's most times no need to adjust the values in this section
# since they can be overridden by host specific sections (see below).
GLOBAL_DEFAULTS = Web2LDAPConfig(

    # Search filter template for smart login
    # Use indexed attributes here!
    binddn_mapping=u'ldap:///_??sub?(|(cn={user})(mail={user})(uid={user})(sAMAccountName={user})(userPrincipalName={user}))',

    # HTML template strings used to bind name in the status section
    # on top of page depending on the object class of an entry.
    boundas_template={
        'inetOrgPerson':r'<strong>%(cn)s</strong> &lt;%(mail)s&gt; (%(uid)s/%(employeeNumber)s)',
        'account':r'<strong>%(uid)s</strong>',
    },

    # Timeout for LDAP operations (seconds)
    timeout=20,

    # Use StartTLS on connect. It's recommended saying 0 as default
    # since not many servers can handle an unknown extended operation properly
    starttls=0,

    # Dictionary for specifying arbitrary TLS-related LDAP options.
    # Which options are really available on your system depends on your ldap0 and OpenLDAP builds.
    # (see section TLS OPTIONS on OpenLDAP's man page ldap_set_option(3)
    tls_options={
        # you should really set this!
        ldap0.OPT_X_TLS_REQUIRE_CERT: ldap0.OPT_X_TLS_DEMAND,
        # Directory containing all the trusted root CA certs (symbolic hash links required!)
        #ldap0.OPT_X_TLS_CACERTDIR: '/var/lib/ca-certificates/pem',
        #ldap0.OPT_X_TLS_CACERTDIR: os.path.join(ETC_DIR, 'tls', 'cacerts'),
        # File containing all the trusted root CA certs
        #ldap0.OPT_X_TLS_CACERTFILE: '/etc/ssl/ca-bundle.pem',
        #ldap0.OPT_X_TLS_CACERTFILE: '/var/lib/ca-certificates/ca-bundle.pem',
        #ldap0.OPT_X_TLS_CIPHER_SUITE: 'HIGH',
        ldap0.OPT_X_TLS_PROTOCOL_MIN: 3,
        #ldap0.OPT_X_TLS_CRLCHECK: ldap0.OPT_X_TLS_CRL_PEER,
        #ldap0.OPT_X_TLS_CRLFILE: os.path.join(ETC_DIR, 'ssl', 'crt', 'peers.crl'),
    },

    # Send session track control
    session_track_control=False,

    # Attributes explicitly requested while doing read
    # and modify operations
    requested_attrs=(
        'structuralObjectClass', 'governingStructureRule', 'subschemaSubentry',
        # password policy attributes
        'passwordExpirationTime', 'passwordExpWarned',
        'passwordRetryCount', 'retryCountResetTime', 'accountUnlockTime',
        'passwordHistory', 'passwordAllowChangeTime',
        # Account specifics
        'nsAccountLock', 'nsLookthroughLimit',
        # ACL attributes
        'aci', 'aclentry',
        # counters
        'hasSubordinates', 'numSubordinates', 'subordinateCount',
        # Dynamic Entries (see RFC 2589)
        'entryTTL',
        # Proxy Authz attributes
        'authzTo', 'authzFrom',
        # password policy attributes
        'pwdPolicySubentry',
        # Sun Directory Server
        'isMemberOf',
        # MS Active Directory
        'nTSecurityDescriptor',
        'tokenGroups', 'tokenGroupsGlobalAndUniversal', 'tokenGroupsNoGCAcceptable',
        'mS-DS-CreatorSID', 'primaryGroupToken', 'canonicalName', 'fromEntry',
        'sDRightsEffective', 'msDS-Approx-Immed-Subordinates', 'msDS-KeyVersionNumber',
        #'msDS-ReplAttributeMetaData',
        #'lastLogonTimestamp', 'lockoutTime',
        #'allowedAttributes', 'allowedAttributesEffective',
        #'allowedChildClasses', 'allowedChildClassesEffective',
        # X.500 DSAs
        'administrativeRole',
    ),

    # List of attribute type names which are supposed to be constant during
    # editing an entry.
    modify_constant_attrs=(
        # Mostly OpenLDAP
        'entryCSN', 'entryDN', 'entryUUID',
        # see RFC
        'createTimestamp', 'modifyTimestamp', 'creatorsName', 'modifiersName',
        # MS AD
        'uSNChanged', 'uSNCreated', 'whenChanged', 'whenCreated',
        # Netscape/Sun DS
        'nsUniqueId',
        # 389 Directory Server also known as Fedora DS
        'entryUSN',
        # eDirectory
        'localEntryID', 'GUID',
    ),

    # vCard template files
    vcard_template={
        # 'object class': 'pathname of vCard template file'
        'person': os.path.join(TEMPLATES_DIR, 'vcard_person.txt'),
        'inetOrgPerson': os.path.join(TEMPLATES_DIR, 'vcard_person.txt'),
        'organization': os.path.join(TEMPLATES_DIR, 'vcard_organization.txt'),
    },

    # HTML template files for printing table entries
    print_template={
        # 'object class': 'pathname of printable HTML template file'
        'person': os.path.join(TEMPLATES_DIR, 'print_person.html'),
        'organization': os.path.join(TEMPLATES_DIR, 'print_organization.html'),
        'organizationalUnit': os.path.join(TEMPLATES_DIR, 'print_organizationalUnit.html'),
    },

    # HTML template file for search options fieldset in search forms
    searchoptions_template=os.path.join(TEMPLATES_DIR, 'searchform_search_options.html'),

    # HTML template file for Basic Search form
    searchform_template={
        '_': os.path.join(TEMPLATES_DIR, 'searchform_base.html'),
        'NIS': os.path.join(TEMPLATES_DIR, 'searchform_nis.html'),
        'DHCP': os.path.join(TEMPLATES_DIR, 'searchform_dhcp.html'),
        'DNS': os.path.join(TEMPLATES_DIR, 'searchform_dns.html'),
        'Kerberos': os.path.join(TEMPLATES_DIR, 'searchform_mit_krb.html'),
        'MS AD': os.path.join(TEMPLATES_DIR, 'searchform_msad.html'),
    },

    # HTML template file for rename form
    rename_template=os.path.join(TEMPLATES_DIR, 'rename.html'),

    # HTML template file for whole top section
    top_template=os.path.join(TEMPLATES_DIR, 'top.html'),

    # HTML template file for password change form
    passwd_template=os.path.join(TEMPLATES_DIR, 'passwd.html'),

    # HTML template file for Login form
    login_template=os.path.join(TEMPLATES_DIR, 'login.html'),

    # Attributes which should be present in attribute select list of advanced search form
    search_attrs=(),

    # HTML template strings used to display entries in the table
    # of search results
    search_tdtemplate={
        'inetOrgPerson':r'%(entryDN)s<br>%(cn)s &lt;%(mail)s&gt;<br>Office: %(telephoneNumber)s, Home: %(homePhone)s, Mobile: %(mobile)s',
        'organization':r'%(entryDN)s<br>%(o)s Tel.: %(telephoneNumber)s',
        'organizationalUnit':r'%(entryDN)s<br>Org. Unit %(ou)s:<br>%(description)s',
        'rfc822MailGroup':r'Mailing list %(cn)s &lt;%(mail)s&gt;, see %(labeledurl)s',
        'account':r'%(entryDN)s<br>Account <strong>%(uid)s</strong>',
        'groupOfNames':r'%(entryDN)s<br>Group <strong>%(cn)s</strong>',
        'groupOfUniqueNames':r'%(entryDN)s<br>Group <strong>%(cn)s</strong>',
        'organizationalRole':r'%(entryDN)s<br>Role <strong>%(cn)s</strong>',
        'posixGroup':r'%(entryDN)s<br>POSIX group <strong>%(cn)s</strong> (%(gidNumber)s)',
        'namedObject':r'%(entryDN)s<br>Named object <strong>%(cn)s - %(uniqueIdentifier)s</strong><br>(%(displayName)s)',
        'sambaDomain':r'%(entryDN)s<br>Samba domain <strong>%(sambaDomainName)s</strong> (%(sambaSID)s)',
        'dnsDomain2':(
            '%(entryDN)s<br>'
            'DNS RR <strong>%(associatedDomain)s</strong>:<br>'
            'A: %(aRecord)s<br>PTR: %(pTRRecord)s<br>CNAME: %(cNAMERecord)s'
        ),
        'dhcpClass':r'%(entryDN)s<br>DHCP class <strong title="%(dhcpComments)s">%(cn)s</strong>',
        'dhcpGroup':r'%(entryDN)s<br>DHCP group <strong title="%(dhcpComments)s">%(cn)s</strong>',
        'dhcpHost':r'%(entryDN)s<br>DHCP host <strong title="%(dhcpComments)s">%(cn)s</strong><br>%(dhcpHWAddress)s<br>%(dhcpStatements)s',
        'dhcpServer':r'%(entryDN)s<br>DHCP server <strong title="%(dhcpComments)s">%(cn)s</strong>',
        'dhcpService':r'%(entryDN)s<br>DHCP service <strong title="%(dhcpComments)s">%(cn)s</strong>',
        'dhcpSharedNetwork':r'%(entryDN)s<br>DHCP shared network <strong title="%(dhcpComments)s">%(cn)s</strong>',
        'dhcpSubClass':r'%(entryDN)s<br>DHCP sub class <strong title="%(dhcpComments)s">%(cn)s</strong><br>%(dhcpClassData)s',
        'dhcpSubnet':r'%(entryDN)s<br>DHCP subnet <strong title="%(dhcpComments)s">%(cn)s/%(dhcpNetMask)s</strong>',
    },

    # Default for number of results shown per page
    search_resultsperpage=10,

    # Parameters for tree-viewer
    # Allow maximum this number of levels
    dit_max_levels=10,
    # Fetch at most this number of entries when searching below a node
    dit_search_sizelimit=50,
    # Timelimit [secs] for searching
    dit_search_timelimit=10,

    # HTML template file used for displaying entries of specific object class
    read_template={
        # 'object class': 'pathname of HTML template file'
        'inetOrgPerson': os.path.join(TEMPLATES_DIR, 'read_inetOrgPerson.html'),
        'account': os.path.join(TEMPLATES_DIR, 'read_account.html'),
        'organizationalPerson': os.path.join(TEMPLATES_DIR, 'read_inetOrgPerson.html'),
        'msPerson': os.path.join(TEMPLATES_DIR, 'read_msPerson.html'),
        'organization': os.path.join(TEMPLATES_DIR, 'read_organization.html'),
        'organizationalUnit': os.path.join(TEMPLATES_DIR, 'read_organizationalUnit.html'),
        'msOrganization': os.path.join(TEMPLATES_DIR, 'read_msOrganization.html'),
        'groupOfNames': os.path.join(TEMPLATES_DIR, 'read_groupOfNames.html'),
        'posixAccount': os.path.join(TEMPLATES_DIR, 'read_posixAccount.html'),
        'posixGroup': os.path.join(TEMPLATES_DIR, 'read_posixGroup.html'),
        'eduPerson': os.path.join(TEMPLATES_DIR, 'read_eduPerson.html'),
        'mailboxRelatedObject': os.path.join(TEMPLATES_DIR, 'read_mailboxRelatedObject.html'),
        'namedObject': os.path.join(TEMPLATES_DIR, 'read_namedObject.html'),
        'namedPolicy': os.path.join(TEMPLATES_DIR, 'read_namedPolicy.html'),
        'pwdPolicy': os.path.join(TEMPLATES_DIR, 'read_pwdPolicy.html'),
        'msPwdResetPolicy': os.path.join(TEMPLATES_DIR, 'read_msPwdResetPolicy.html'),
        'sambaDomain': os.path.join(TEMPLATES_DIR, 'read_sambaDomain.html'),
        'sambaSamAccount': os.path.join(TEMPLATES_DIR, 'read_sambaSamAccount.html'),
        'sambaGroupMapping': os.path.join(TEMPLATES_DIR, 'read_sambaGroupMapping.html'),
        'dhcpHost': os.path.join(TEMPLATES_DIR, 'dhcp', 'read_dhcpHost.html'),
        'dhcpServer': os.path.join(TEMPLATES_DIR, 'dhcp', 'read_dhcpServer.html'),
        'dhcpService': os.path.join(TEMPLATES_DIR, 'dhcp', 'read_dhcpService.html'),
        'dhcpSubnet': os.path.join(TEMPLATES_DIR, 'dhcp', 'read_dhcpSubnet.html'),
        'inetLocalMailRecipient': os.path.join(TEMPLATES_DIR, 'read_inetLocalMailRecipient.html'),
        'oathHOTPUser': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathHOTPUser.html'),
        'oathTOTPUser': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathTOTPUser.html'),
        'oathHOTPToken': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathHOTPToken.html'),
        'oathTOTPToken': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathTOTPToken.html'),
        'oathParams': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathParams.html'),
        'oathHOTPParams': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathHOTPParams.html'),
        'oathTOTPParams': os.path.join(TEMPLATES_DIR, 'oath', 'read_oathTOTPParams.html'),
    },

    # Maximum count of attribute values displayed when displaying a single entry
    # without attribute values being expanded
    read_tablemaxcount={
        'allowedAttributes':2,
        'allowedAttributesEffective':2,
        'allowedChildClasses':2,
        'allowedChildClassesEffective':2,
        'member':40,
        'memberOf':30,
        'memberUid':40,
        'pwdHistory':2,
        'roleOccupant':40,
        'msDS-ReplAttributeMetaData':1,
        'tokenGroups':4,
        'tokenGroupsGlobalAndUniversal':4,
        'tokenGroupsNoGCAcceptable':4,
        'uniqueMember':40,
    },

    # HTML template file used for displaying input forms for entries
    # of specific object class
    input_template={
        # 'object class': 'pathname of HTML template file'
        'inetOrgPerson': os.path.join(TEMPLATES_DIR, 'inputform_inetOrgPerson.html'),
        'account': os.path.join(TEMPLATES_DIR, 'inputform_account.html'),
        'msPerson': os.path.join(TEMPLATES_DIR, 'inputform_msPerson.html'),
        'posixAccount': os.path.join(TEMPLATES_DIR, 'inputform_posixAccount.html'),
        'posixGroup': os.path.join(TEMPLATES_DIR, 'inputform_posixGroup.html'),
        'organization': os.path.join(TEMPLATES_DIR, 'inputform_organization.html'),
        'organizationalUnit': os.path.join(TEMPLATES_DIR, 'inputform_organizationalUnit.html'),
        'msOrganization': os.path.join(TEMPLATES_DIR, 'inputform_msOrganization.html'),
        'groupOfNames': os.path.join(TEMPLATES_DIR, 'inputform_groupOfNames.html'),
        'eduPerson': os.path.join(TEMPLATES_DIR, 'inputform_eduPerson.html'),
        'mailboxRelatedObject': os.path.join(TEMPLATES_DIR, 'inputform_mailboxRelatedObject.html'),
        'namedObject': os.path.join(TEMPLATES_DIR, 'inputform_namedObject.html'),
        'namedPolicy': os.path.join(TEMPLATES_DIR, 'inputform_namedPolicy.html'),
        'pwdPolicy': os.path.join(TEMPLATES_DIR, 'inputform_pwdPolicy.html'),
        'msPwdResetPolicy': os.path.join(TEMPLATES_DIR, 'inputform_msPwdResetPolicy.html'),
        'sambaDomain': os.path.join(TEMPLATES_DIR, 'inputform_sambaDomain.html'),
        'sambaSamAccount': os.path.join(TEMPLATES_DIR, 'inputform_sambaSamAccount.html'),
        'sambaGroupMapping': os.path.join(TEMPLATES_DIR, 'inputform_sambaGroupMapping.html'),
        'dhcpHost': os.path.join(TEMPLATES_DIR, 'dhcp', 'inputform_dhcpHost.html'),
        'dhcpServer': os.path.join(TEMPLATES_DIR, 'dhcp', 'inputform_dhcpServer.html'),
        'dhcpService': os.path.join(TEMPLATES_DIR, 'dhcp', 'inputform_dhcpService.html'),
        'dhcpSubnet': os.path.join(TEMPLATES_DIR, 'dhcp', 'inputform_dhcpSubnet.html'),
        'dNSDomain2': os.path.join(TEMPLATES_DIR, 'inputform_dNSDomain2.html'),
        'inetLocalMailRecipient': os.path.join(TEMPLATES_DIR, 'inputform_inetLocalMailRecipient.html'),
        'oathHOTPUser': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathHOTPUser.html'),
        'oathTOTPUser': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathTOTPUser.html'),
        'oathHOTPToken': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathHOTPToken.html'),
        'oathTOTPToken': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathTOTPToken.html'),
        'oathParams': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathParams.html'),
        'oathHOTPParams': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathHOTPParams.html'),
        'oathTOTPParams': os.path.join(TEMPLATES_DIR, 'oath', 'inputform_oathTOTPParams.html'),
    },

    # Number of columns for print output
    print_cols=4,

    # Parameters for password generation
    # Unicode string containing all valid characters used when generating
    # password values
    passwd_genchars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    # Length of generated password
    passwd_genlength=24,

    # Dictionary { description : LDIF file name } for displaying
    # link for quickly choosing LDIF templates for new entries
    addform_entry_templates={
        'Person / Contact': os.path.join(TEMPLATES_DIR, 'add_person.ldif'),
        'Organization (Company etc.)': os.path.join(TEMPLATES_DIR, 'add_organization.ldif'),
        'Organizational Unit': os.path.join(TEMPLATES_DIR, 'add_orgunit.ldif'),
        'Group': os.path.join(TEMPLATES_DIR, 'add_group.ldif'),
        'Locality': os.path.join(TEMPLATES_DIR, 'add_locality.ldif'),
        'POSIX user': os.path.join(TEMPLATES_DIR, 'add_user.ldif'),
        'Mail user': os.path.join(TEMPLATES_DIR, 'add_mailaccount.ldif'),
        'DNS sub-domain': os.path.join(TEMPLATES_DIR, 'add_dnsdomain2.ldif'),
        'DNS zone (SOA)': os.path.join(TEMPLATES_DIR, 'add_dnsdomain2_soa.ldif'),
        'Application process': os.path.join(TEMPLATES_DIR, 'add_applicationprocess.ldif'),
    },

    # HTML template strings used to display the superior entry
    # in the input form when adding/modifying entries
    inputform_supentrytemplate={
        'organization':r'Organization <strong>%(o)s</strong>',
        'organizationalUnit':r'Organizational Unit <strong>%(ou)s</strong>',
    },

    # Named set of LDAP URLs for searching new superior DN when renaming an entry
    rename_supsearchurl={
        'Search current naming context for organizationalUnit': 'ldap:///_??sub?(objectClass=organizationalUnit)',
        'Search current naming context for organization': 'ldap:///_??sub?(objectClass=organization)',
        'Search current naming context for locality': 'ldap:///_??sub?(objectClass=locality)',
        'Search current naming context for domain': 'ldap:///_??sub?(objectClass=domain)',
        'Search below superior entry for organizationalUnit': 'ldap:///..??sub?(objectClass=organizationalUnit)',
        'Search below superior entry for organization': 'ldap:///..??sub?(objectClass=organization)',
        'Search below superior entry for locality': 'ldap:///..??sub?(objectClass=locality)',
        'Search below superior entry for domain': 'ldap:///..??sub?(objectClass=domain)',
    },

    # LDIF file used as locally stored pseudo LDAPv3 schema
    schema_uri='file:'+os.path.join(ETC_DIR, 'localschema.ldif'),

    # Whether to apply strict subschema consistency check (e.g. uniqueness)
    schema_strictcheck=True,

    # The definitions for group entry administration
    groupadm_filterstr_template=r'(|%s)',
    groupadm_optgroup_bounds=(1, None),
    groupadm_defs={
        'groupOfNames': ('member', None),
        'groupOfUniqueNames': ('uniqueMember', None),
        'organizationalRole': ('roleOccupant', None),
        'rfc822MailGroup': ('mail', 'mail'),
        'nisMailAlias': ('rfc822MailMember', 'mail'),
        'mailGroup': ('mgrprfc822mailmember', 'mail'),
        # Found on IBM SecureWay Directory
        'accessGroup': ('member', None),
        # RFC2370
        'posixGroup': ('memberUid', 'uid'),
        'nisNetgroup': ('memberNisNetgroup', 'uid'),
        # Samba 3.0
        #'sambaGroupMapping': ('sambaSIDList', 'sambaSID'),
        # Active Directory
        'group':    ('member', None),
        # draft-findlay-ldap-groupofentries
        'groupOfEntries': ('member', None),
        # Apple MAC OS X
        'apple-group': ('apple-group-memberguid', 'apple-generateduid'),
    },

)

########################################################################
# LDAP host(s) with their defaults can be pre-defined as dictionary
# ldap_def = {'host:port':{paramdictionary}}
# You can use preset configuration instance declared above herein
########################################################################

ldap_def = {

    '_': GLOBAL_DEFAULTS,

    'ldap://localhost': Web2LDAPConfig(
        description='My poorly configured LDAP host',
    ),

    'ldap://ipa.demo1.freeipa.org': Web2LDAPConfig(
        description='FreeIPA demo host',
        # work around 389-DS bug here
        schema_strictcheck=False,
    ),

    # Example for OpenLDAP's accesslog database
    'ldap:///cn=accesslog': OPENLDAP_ACCESSLOG_CONFIG,

    # Example for changelog database
    'ldap:///cn=changelog': CHANGELOG_CONFIG,

    # Example for cn=Monitor covering various server implementations
    'ldap:///cn=Monitor': OPENLDAP_MONITOR_CONFIG,

    # For dynamic configuration via cn=config
    'ldap:///cn=config': CN_CONFIG,

    # AE-DIR's main DB
    'ldap:///ou=ae-dir': AE_DIR_CONFIG,

    # AE-DIR's accesslog (override description)
    'ldap:///cn=accesslog-ae-dir': OPENLDAP_ACCESSLOG_CONFIG.clone(
        description='\xC6-DIR accesslog',
    ),

    # AE-DIR's online demo
    #-----------------------------------------------------------------------

    # This creates a new config based on config preset instance
    # AE_DIR_CONFIG and just sets a specific description
    'ldaps://demo.ae-dir.com/ou=ae-dir': AE_DIR_CONFIG.clone(
        description='\xC6-DIR demo',
    ),

}

# You can apply sections defined above to other configuration keys
#---------------------------------------------------------------------------

# another cloned config for setting specific LDAPS parameters for public AE-DIR demo server
ldap_def['ldaps://demo.ae-dir.com'] = ldap_def['ldaps://demo.ae-dir.com/ou=ae-dir'].clone(
    tls_options={
        ldap0.OPT_X_TLS_CACERTFILE: os.path.join(ETC_DIR, 'tls', 'cacerts', 'ISRG_Root_X1.pem'),
    },
)
# another cloned config for mandating use of StartTLS ext.op.
ldap_def['ldap://demo.ae-dir.com'] = ldap_def['ldaps://demo.ae-dir.com'].clone(
    starttls=2,
)

# set MS AD configuration presets for all AD LDAP URIs
from ldap0.dn import DNObj
from ldap0.ldapurl import LDAPUrl

AD_DOMAINS = (
#    'adt1.example.com',
)

for ad_domain in AD_DOMAINS:
    ad_dn = DNObj.from_domain(ad_domain)
    ad_url = str(
        LDAPUrl(
            urlscheme='ldap',
            dn=str(ad_dn),
        )
    )
    ldap_def[ad_url] = MSAD_CONFIG.clone(
        description='AD domain %s' % (ad_domain),
    )
    for ad_sub_dn in (
            'CN=Configuration',
            'CN=Schema,CN=Configuration',
            'DC=DomainDnsZones',
            'DC=ForestDnsZones',
        ):
        ldap_def[str(
            LDAPUrl(
                urlscheme='ldap',
                dn=str(DNObj.from_str(ad_sub_dn)+ad_dn),
            )
        )] = ldap_def[ad_url]
