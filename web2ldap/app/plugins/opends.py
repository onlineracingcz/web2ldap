# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for OpenDS and OpenDJ
"""

from __future__ import absolute_import

import re

import ldap0
import ldap0.cidict

from web2ldap.ldaputil.base import explode_dn, rdn_dict
from web2ldap.app.schema.syntaxes import \
    BindDN, \
    DirectoryString, \
    DynamicDNSelectList, \
    MultilineText, \
    OctetString, \
    SelectList, \
    syntax_registry
from web2ldap.app.plugins.x509 import Certificate
from web2ldap.app.plugins.groups import MemberOf
from web2ldap.app.plugins.quirks import NamingContexts
from web2ldap.mspki.util import HexString
from web2ldap.app.schema import no_humanreadable_attr


syntax_registry.reg_at(
    MemberOf.oid, [
        '1.3.6.1.4.1.42.2.27.9.1.792', # isMemberOf
    ]
)


class OpenDSCfgPasswordPolicy(DynamicDNSelectList):
    oid = 'OpenDSCfgPasswordPolicy-oid'
    desc = 'DN of the ds-cfg-password-policy entry'
    ldap_url = 'ldap:///cn=Password Policies,cn=config?cn?one?(objectClass=ds-cfg-password-policy)'

syntax_registry.reg_at(
    OpenDSCfgPasswordPolicy.oid, [
        '1.3.6.1.4.1.26027.1.1.161', # ds-cfg-default-password-policy
        '1.3.6.1.4.1.26027.1.1.244', # ds-pwp-password-policy-dn
    ]
)


class OpenDSCfgPasswordStorageScheme(DynamicDNSelectList):
    oid = 'OpenDSCfgPasswordStorageScheme-oid'
    desc = 'DN of the ds-cfg-password-storage-scheme entry'
    ldap_url = 'ldap:///cn=Password Storage Schemes,cn=config?cn?one?(objectClass=ds-cfg-password-storage-scheme)'

syntax_registry.reg_at(
    OpenDSCfgPasswordStorageScheme.oid, [
        '1.3.6.1.4.1.26027.1.1.137', # ds-cfg-default-password-storage-scheme
    ]
)

class OpenDSCfgPasswordGenerator(DynamicDNSelectList):
    oid = 'OpenDSCfgPasswordGenerator-oid'
    desc = 'DN of the ds-cfg-password-generator entry'
    ldap_url = 'ldap:///cn=Password Generators,cn=config?cn?one?(objectClass=ds-cfg-password-generator)'

syntax_registry.reg_at(
    OpenDSCfgPasswordGenerator.oid, [
        '1.3.6.1.4.1.26027.1.1.153', # ds-cfg-password-generator
    ]
)


class OpenDSCfgIdentityMapper(DynamicDNSelectList):
    oid = 'OpenDSCfgIdentityMapper-oid'
    desc = 'DN of the ds-cfg-identity-mapper entry'
    ldap_url = 'ldap:///cn=Identity Mappers,cn=config?cn?one?(objectClass=ds-cfg-identity-mapper)'

syntax_registry.reg_at(
    OpenDSCfgIdentityMapper.oid, [
        '1.3.6.1.4.1.26027.1.1.113', # ds-cfg-identity-mapper
        '1.3.6.1.4.1.26027.1.1.114', # ds-cfg-proxied-authorization-identity-mapper
    ]
)


class OpenDSCfgCertificateMapper(DynamicDNSelectList):
    oid = 'OpenDSCfgCertificateMapper-oid'
    desc = 'DN of the ds-cfg-certificate-mapper entry'
    ldap_url = 'ldap:///cn=Certificate Mappers,cn=config?cn?one?(objectClass=ds-cfg-certificate-mapper)'

syntax_registry.reg_at(
    OpenDSCfgCertificateMapper.oid, [
        '1.3.6.1.4.1.26027.1.1.262', # ds-cfg-certificate-mapper
    ]
)


class OpenDSCfgKeyManagerProvider(DynamicDNSelectList):
    oid = 'OpenDSCfgKeyManagerProvider-oid'
    desc = 'DN of the ds-cfg-key-manager-provider entry'
    ldap_url = 'ldap:///cn=Key Manager Providers,cn=config?cn?one?(objectClass=ds-cfg-key-manager-provider)'

syntax_registry.reg_at(
    OpenDSCfgKeyManagerProvider.oid, [
        '1.3.6.1.4.1.26027.1.1.263', # ds-cfg-key-manager-provider
    ]
)


class OpenDSCfgTrustManagerProvider(DynamicDNSelectList):
    oid = 'OpenDSCfgTrustManagerProvider-oid'
    desc = 'DN of the ds-cfg-trust-manager-provider entry'
    ldap_url = 'ldap:///cn=Trust Manager Providers,cn=config?cn?one?(objectClass=ds-cfg-trust-manager-provider)'

syntax_registry.reg_at(
    OpenDSCfgTrustManagerProvider.oid, [
        '1.3.6.1.4.1.26027.1.1.264', # ds-cfg-trust-manager-provider
    ]
)


class OpenDSCfgSSLClientAuthPolicy(SelectList):
    oid = 'OpenDSCfgSSLClientAuthPolicy-oid'
    desc = 'Specifies the policy regarding client SSL certificates'
    attr_value_dict = {
        u'disabled': u'Client certificate is not requested',
        u'optional': u'Client certificate is requested but not required',
        u'required': u'Client certificate is required',
    }

syntax_registry.reg_at(
    OpenDSCfgSSLClientAuthPolicy.oid, [
        '1.3.6.1.4.1.26027.1.1.90', # ds-cfg-ssl-client-auth-policy
    ]
)


class OpenDSCfgSNMPSecurityLevel(SelectList):
    oid = 'OpenDSCfgSNMPSecurityLevel-oid'
    desc = 'Specifies the policy regarding client SSL certificates'
    attr_value_dict = {
        u'authnopriv': u'Authentication activated with no privacy.',
        u'authpriv': u'Authentication with privacy activated.',
        u'noauthnopriv': u'No security mechanisms activated.',
    }

syntax_registry.reg_at(
    OpenDSCfgSNMPSecurityLevel.oid, [
        '1.3.6.1.4.1.26027.1.1.452', # ds-cfg-security-level
    ]
)


class OpenDSCfgInvalidSchemaBehaviour(SelectList):
    oid = 'OpenDSCfgInvalidSchemaBehaviour-oid'
    desc = 'Specifies how OpenDS behaves in case of schema errors'
    attr_value_dict = {
        u'reject': u'reject',
        u'default': u'default',
        u'accept': u'accept',
        u'warn': u'warn',
    }

syntax_registry.reg_at(
    OpenDSCfgInvalidSchemaBehaviour.oid, [
        '1.3.6.1.4.1.26027.1.1.31', # ds-cfg-invalid-attribute-syntax-behavior
        '1.3.6.1.4.1.26027.1.1.88', # ds-cfg-single-structural-objectclass-behavior
    ]
)


class OpenDSCfgEtimeResolution(SelectList):
    oid = 'OpenDSCfgEtimeResolution-oid'
    desc = 'Specifies the resolution to use for operation elapsed processing time (etime) measurements.'
    attr_value_dict = {
        u'milliseconds': u'milliseconds',
        u'nanoseconds': u'nanoseconds',
    }

syntax_registry.reg_at(
    OpenDSCfgEtimeResolution.oid, [
        '1.3.6.1.4.1.26027.1.1.442', # ds-cfg-etime-resolution
    ]
)


class OpenDSCfgWritabilityMode(SelectList):
    oid = 'OpenDSCfgWritabilityMode-oid'
    desc = 'Specifies the kinds of write operations the Directory Server can process.'
    attr_value_dict = {
        u'disabled': u'all write operations are rejected',
        u'enabled': u'all write operations are processed',
        u'internal-only': u'write operations requested as internal/sync operations are processed',
    }

syntax_registry.reg_at(
    OpenDSCfgWritabilityMode.oid, [
        '1.3.6.1.4.1.26027.1.1.123', # ds-cfg-writability-mode
    ]
)


class OpenDSCfgCertificateValidationPolicy(SelectList):
    oid = 'OpenDSCfgCertificateValidationPolicy-oid'
    desc = 'Specifies the way client certs are checked in user entry.'
    attr_value_dict = {
        u'always': u"Always require matching peer certificate in user's entry",
        u'ifpresent': u"Require one matching certificate if attribute exists in user's entry",
        u'never': u"Peer certificate is not checked in user's entry at all",
    }

syntax_registry.reg_at(
    OpenDSCfgCertificateValidationPolicy.oid, [
        '1.3.6.1.4.1.26027.1.1.16', # ds-cfg-certificate-validation-policy
    ]
)


class OpenDSCfgAccountStatusNotificationType(SelectList):
    oid = 'OpenDSCfgAccountStatusNotificationType-oid'
    desc = 'Specifies when the generate a notification about account status'
    attr_value_dict = {
        u'account-disabled': u'User account has been disabled by an administrator',
        u'account-enabled': u'User account has been enabled by an administrator',
        u'account-expired': u'User authentication has failed because the account has expired',
        u'account-idle-locked': u'User account has been locked because it was idle for too long',
        u'account-permanently-locked': u'User account has been permanently locked after too many failed attempts',
        u'account-reset-locked': u'User account has been locked, because the password had been reset by an administrator but not changed by the User within the required interval',
        u'account-temporarily-locked': u'User account has been temporarily locked after too many failed attempts',
        u'account-unlocked': u'User account has been unlocked by an administrator',
        u'password-changed': u'User changes his/her own password',
        u'password-expired': u'User authentication has failed because the password has expired',
        u'password-expiring':u"Password expiration warning is encountered for user's password for the first time.",
        u'password-reset':u"User's password was reset by an administrator.",
    }

syntax_registry.reg_at(
    OpenDSCfgAccountStatusNotificationType.oid, [
        '1.3.6.1.4.1.26027.1.1.238', # ds-cfg-account-status-notification-type
    ]
)


class OpenDSCfgSslProtocol(SelectList):
    oid = 'OpenDSCfgSslProtocol-oid'
    desc = 'Specifies the SSL/TLS protocols supported.'
    attr_value_dict = {
        u'SSL':    u'any version of SSL',
        u'SSLv2':  u'SSL version 2 or higher',
        u'SSLv3':  u'SSL version 3',
        u'TLS':    u'any version of TLS',
        u'TLSv1':  u'TLS version 1.0 (RFC 2246)',
        u'TLSv1.1': u'TLS version 1.1 (RFC 4346)',
    }

syntax_registry.reg_at(
    OpenDSCfgSslProtocol.oid, [
        '1.3.6.1.4.1.26027.1.1.391', # ds-cfg-ssl-protocol
    ]
)


class OpenDSCfgSslCipherSuite(SelectList):
    oid = 'OpenDSCfgSslCipherSuite-oid'
    desc = 'Specifies the used cipher suites.'
    attr_value_dict = {
        u'SSL_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA': u'SSL_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
        u'SSL_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA': u'SSL_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
        u'SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA': u'SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
        u'SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA': u'SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
        u'SSL_DHE_DSS_WITH_DES_CBC_SHA': u'SSL_DHE_DSS_WITH_DES_CBC_SHA',
        u'SSL_DHE_DSS_WITH_RC4_128_SHA': u'SSL_DHE_DSS_WITH_RC4_128_SHA',
        u'SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA': u'SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
        u'SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA': u'SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
        u'SSL_DHE_RSA_WITH_DES_CBC_SHA': u'SSL_DHE_RSA_WITH_DES_CBC_SHA',
        u'SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA': u'SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
        u'SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA': u'SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA',
        u'SSL_DH_DSS_WITH_DES_CBC_SHA': u'SSL_DH_DSS_WITH_DES_CBC_SHA',
        u'SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA': u'SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
        u'SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA': u'SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA',
        u'SSL_DH_RSA_WITH_DES_CBC_SHA': u'SSL_DH_RSA_WITH_DES_CBC_SHA',
        u'SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA': u'SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
        u'SSL_DH_anon_EXPORT_WITH_RC4_40_MD5': u'SSL_DH_anon_EXPORT_WITH_RC4_40_MD5',
        u'SSL_DH_anon_WITH_3DES_EDE_CBC_SHA': u'SSL_DH_anon_WITH_3DES_EDE_CBC_SHA',
        u'SSL_DH_anon_WITH_DES_CBC_SHA': u'SSL_DH_anon_WITH_DES_CBC_SHA',
        u'SSL_DH_anon_WITH_RC4_128_MD5': u'SSL_DH_anon_WITH_RC4_128_MD5',
        u'SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA': u'SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA',
        u'SSL_FORTEZZA_DMS_WITH_NULL_SHA': u'SSL_FORTEZZA_DMS_WITH_NULL_SHA',
        u'SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA': u'SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA',
        u'SSL_RSA_EXPORT1024_WITH_RC4_56_SHA': u'SSL_RSA_EXPORT1024_WITH_RC4_56_SHA',
        u'SSL_RSA_EXPORT_WITH_DES40_CBC_SHA': u'SSL_RSA_EXPORT_WITH_DES40_CBC_SHA',
        u'SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5': u'SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
        u'SSL_RSA_EXPORT_WITH_RC4_40_MD5': u'SSL_RSA_EXPORT_WITH_RC4_40_MD5',
        u'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA': u'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
        u'SSL_RSA_FIPS_WITH_DES_CBC_SHA': u'SSL_RSA_FIPS_WITH_DES_CBC_SHA',
        u'SSL_RSA_WITH_3DES_EDE_CBC_SHA': u'SSL_RSA_WITH_3DES_EDE_CBC_SHA',
        u'SSL_RSA_WITH_DES_CBC_SHA': u'SSL_RSA_WITH_DES_CBC_SHA',
        u'SSL_RSA_WITH_IDEA_CBC_SHA': u'SSL_RSA_WITH_IDEA_CBC_SHA',
        u'SSL_RSA_WITH_NULL_MD5': u'SSL_RSA_WITH_NULL_MD5',
        u'SSL_RSA_WITH_NULL_SHA': u'SSL_RSA_WITH_NULL_SHA',
        u'SSL_RSA_WITH_RC4_128_MD5': u'SSL_RSA_WITH_RC4_128_MD5',
        u'SSL_RSA_WITH_RC4_128_SHA': u'SSL_RSA_WITH_RC4_128_SHA',
        u'TLS_DHE_DSS_WITH_AES_128_CBC_SHA': u'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
        u'TLS_DHE_DSS_WITH_AES_256_CBC_SHA': u'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
        u'TLS_DHE_RSA_WITH_AES_128_CBC_SHA': u'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        u'TLS_DHE_RSA_WITH_AES_256_CBC_SHA': u'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
        u'TLS_DH_anon_WITH_AES_128_CBC_SHA': u'TLS_DH_anon_WITH_AES_128_CBC_SHA',
        u'TLS_DH_anon_WITH_AES_256_CBC_SHA': u'TLS_DH_anon_WITH_AES_256_CBC_SHA',
        u'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5': u'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
        u'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA': u'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
        u'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5': u'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
        u'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA': u'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
        u'TLS_KRB5_EXPORT_WITH_RC4_40_MD5': u'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
        u'TLS_KRB5_EXPORT_WITH_RC4_40_SHA': u'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
        u'TLS_KRB5_WITH_3DES_EDE_CBC_MD5': u'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
        u'TLS_KRB5_WITH_3DES_EDE_CBC_SHA': u'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
        u'TLS_KRB5_WITH_DES_CBC_MD5': u'TLS_KRB5_WITH_DES_CBC_MD5',
        u'TLS_KRB5_WITH_DES_CBC_SHA': u'TLS_KRB5_WITH_DES_CBC_SHA',
        u'TLS_KRB5_WITH_IDEA_CBC_MD5': u'TLS_KRB5_WITH_IDEA_CBC_MD5',
        u'TLS_KRB5_WITH_IDEA_CBC_SHA': u'TLS_KRB5_WITH_IDEA_CBC_SHA',
        u'TLS_KRB5_WITH_RC4_128_MD5': u'TLS_KRB5_WITH_RC4_128_MD5',
        u'TLS_KRB5_WITH_RC4_128_SHA': u'TLS_KRB5_WITH_RC4_128_SHA',
        u'TLS_RSA_WITH_AES_128_CBC_SHA': u'TLS_RSA_WITH_AES_128_CBC_SHA',
        u'TLS_RSA_WITH_AES_256_CBC_SHA': u'TLS_RSA_WITH_AES_256_CBC_SHA',
    }

syntax_registry.reg_at(
    OpenDSCfgSslCipherSuite.oid, [
        '1.3.6.1.4.1.26027.1.1.392', # ds-cfg-ssl-cipher-suite
    ]
)


class OpenDSCfgPrivilege(SelectList):
    oid = 'OpenDSCfgPrivilege-oid'
    desc = 'Specifies the name of a privilege that should not be evaluated by the server.'
    attr_value_dict = {
        u'backend-backup': u'Request backup tasks',
        u'backend-restore': u'Request restore tasks',
        u'bypass-acl': u'Bypass access control checks',
        u'bypass-lockdown': u'Bypass server lockdown mode',
        u'cancel-request': u'Cancel operations of other client connections',
        u'config-read': u'Read server configuration',
        u'config-write': u'Update the server configuration',
        u'data-sync': u'Participate in data synchronization',
        u'disconnect-client': u'Terminate other client connections',
        u'jmx-notify': u'Subscribe to receive JMX notifications',
        u'jmx-read': u'Perform JMX read operations',
        u'jmx-write': u'Perform JMX write operations',
        u'ldif-export': u'Request LDIF export tasks',
        u'ldif-import': u'Request LDIF import tasks',
        u'modify-acl':u"Modify the server's access control configuration",
        u'password-reset': u'Reset user passwords',
        u'privilege-change': u'Make changes to specific root privileges and user privileges',
        u'proxied-auth': u'Use proxied authorization control or SASL authz ID',
        u'server-lockdown': u'Lockdown a server',
        u'server-restart': u'Request server to perform an in-core restart',
        u'server-shutdown': u'Request server shut down',
        u'subentry-write': u'Perform write ops on LDAP subentries',
        u'unindexed-search': u'Request unindexed searches',
        u'update-schema': u'Change server schema',
    }


syntax_registry.reg_at(
    OpenDSCfgPrivilege.oid, [
        '1.3.6.1.4.1.26027.1.1.261', # ds-cfg-default-root-privilege-name
        '1.3.6.1.4.1.26027.1.1.387', # ds-cfg-disabled-privilege
        '1.3.6.1.4.1.26027.1.1.260', # ds-privilege-name
    ]
)


class OpenDSCfgTimeInterval(DirectoryString):
    oid = 'OpenDSCfgTimeInterval-oid'
    desc = 'A time interval consisting of integer value and time unit'
    reObj = re.compile('^[0-9]+ (seconds|minutes|hours|days)$')

syntax_registry.reg_at(
    OpenDSCfgTimeInterval.oid, [
        '1.3.6.1.4.1.26027.1.1.142', # ds-cfg-idle-lockout-interval
        '1.3.6.1.4.1.26027.1.1.145', # ds-cfg-lockout-duration
        '1.3.6.1.4.1.26027.1.1.147', # ds-cfg-lockout-failure-expiration-interval
        '1.3.6.1.4.1.26027.1.1.148', # ds-cfg-max-password-age
        '1.3.6.1.4.1.26027.1.1.149', # ds-cfg-max-password-reset-age
        '1.3.6.1.4.1.26027.1.1.150', # ds-cfg-min-password-age
        '1.3.6.1.4.1.26027.1.1.152', # ds-cfg-password-expiration-warning-interval
        '1.3.6.1.4.1.26027.1.1.375', # ds-cfg-password-history-duration
        '1.3.6.1.4.1.26027.1.1.115', # ds-cfg-time-limit
    ]
)

class OpenDSSyncHist(OctetString, DirectoryString):
    oid = 'OpenDSSyncHist-oid'
    desc = 'List of modifications'

    def displayValue(self, valueindex=0, commandbutton=False):
        try:
            mod_attr_type, mod_number, mod_type, mod_value = self.attrValue.split(':', 3)
        except ValueError:
            return OctetString.displayValue(self, valueindex, commandbutton)
        first_str = self._form.utf2display(
            ':'.join((mod_attr_type, mod_number, mod_type)).decode(self._ls.charset)
        )
        if no_humanreadable_attr(self._schema, mod_attr_type):
            mod_value_html = HexString(
                mod_value,
                delimiter=':', wrap=64, linesep='<br>\n'
            )[:-1]
        else:
            mod_value_html = self._form.utf2display(mod_value.decode(self._ls.charset))
        return ':<br>'.join((first_str, mod_value_html))

syntax_registry.reg_at(
    OpenDSSyncHist.oid, [
        '1.3.6.1.4.1.26027.1.1.119', # ds-sync-hist
    ]
)


class OpenDSdsCfgAlternatebindDn(BindDN):
    oid = 'OpenDSdsCfgAlternatebindDn-oid'
    desc = 'OpenDS/OpenDJ alternative bind DN'

    def formValue(self):
        if not self.attrValue:
            return u''
        entry = ldap0.cidict.cidict(self._entry)
        attr_value = self.attrValue.decode(self._ls.charset)
        try:
            dn_comp_list = explode_dn(attr_value)
        except ldap0.DECODING_ERROR:
            result = BindDN.formValue(self)
        else:
            try:
                rdn = rdn_dict(dn_comp_list[0])
            except ldap0.DECODING_ERROR:
                result = BindDN.formValue(self)
            else:
                new_rdn = u'+'.join([
                    u'='.join((
                        rdn_attr,
                        rdn_value[0] or entry.get(rdn_attr, [u''])[0]
                    ))
                    for rdn_attr, rdn_value in rdn.items()
                ])
                new_dn_comp_list = [new_rdn]
                new_dn_comp_list.extend(dn_comp_list[1:])
                result = u','.join(new_dn_comp_list)
        return result

syntax_registry.reg_at(
    OpenDSdsCfgAlternatebindDn.oid, [
        '1.3.6.1.4.1.26027.1.1.13', # ds-cfg-alternate-bind-dn
    ]
)


# cn=changelog
#------------------------

class ChangeLogChanges(MultilineText):
    oid = 'ChangeLogChanges-oid'
    desc = 'a set of changes to apply to an entry'
    lineSep = '\n'
    cols = 77

syntax_registry.reg_at(
    ChangeLogChanges.oid, [
        '2.16.840.1.113730.3.1.8', # changes
    ]
)


# Register some more attribute types
#-----------------------------------

syntax_registry.reg_at(
    Certificate.oid, [
        '1.3.6.1.4.1.26027.1.1.408', # ds-cfg-public-key-certificate
    ]
)


syntax_registry.reg_at(
    NamingContexts.oid,
    [
        '1.3.6.1.4.1.26027.1.1.246', # ds-private-naming-contexts
        '1.3.6.1.4.1.26027.1.1.8',   # ds-cfg-base-dn
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
