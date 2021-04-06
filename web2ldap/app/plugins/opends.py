# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for OpenDS and OpenDJ
"""

import re
from typing import Dict

import ldap0
from ldap0.dn import DNObj

from ..schema.syntaxes import (
    BindDN,
    DirectoryString,
    DynamicDNSelectList,
    MultilineText,
    OctetString,
    SelectList,
    syntax_registry,
)
from .x509 import Certificate
from .groups import MemberOf
from .quirks import NamingContexts
from ..schema import no_humanreadable_attr


syntax_registry.reg_at(
    MemberOf.oid, [
        '1.3.6.1.4.1.42.2.27.9.1.792', # isMemberOf
    ]
)


class OpenDSCfgPasswordPolicy(DynamicDNSelectList):
    oid: str = 'OpenDSCfgPasswordPolicy-oid'
    desc: str = 'DN of the ds-cfg-password-policy entry'
    ldap_url = 'ldap:///cn=Password Policies,cn=config?cn?one?(objectClass=ds-cfg-password-policy)'

syntax_registry.reg_at(
    OpenDSCfgPasswordPolicy.oid, [
        '1.3.6.1.4.1.26027.1.1.161', # ds-cfg-default-password-policy
        '1.3.6.1.4.1.26027.1.1.244', # ds-pwp-password-policy-dn
    ]
)


class OpenDSCfgPasswordStorageScheme(DynamicDNSelectList):
    oid: str = 'OpenDSCfgPasswordStorageScheme-oid'
    desc: str = 'DN of the ds-cfg-password-storage-scheme entry'
    ldap_url = 'ldap:///cn=Password Storage Schemes,cn=config?cn?one?(objectClass=ds-cfg-password-storage-scheme)'

syntax_registry.reg_at(
    OpenDSCfgPasswordStorageScheme.oid, [
        '1.3.6.1.4.1.26027.1.1.137', # ds-cfg-default-password-storage-scheme
    ]
)


class OpenDSCfgPasswordGenerator(DynamicDNSelectList):
    oid: str = 'OpenDSCfgPasswordGenerator-oid'
    desc: str = 'DN of the ds-cfg-password-generator entry'
    ldap_url = 'ldap:///cn=Password Generators,cn=config?cn?one?(objectClass=ds-cfg-password-generator)'

syntax_registry.reg_at(
    OpenDSCfgPasswordGenerator.oid, [
        '1.3.6.1.4.1.26027.1.1.153', # ds-cfg-password-generator
    ]
)


class OpenDSCfgIdentityMapper(DynamicDNSelectList):
    oid: str = 'OpenDSCfgIdentityMapper-oid'
    desc: str = 'DN of the ds-cfg-identity-mapper entry'
    ldap_url = 'ldap:///cn=Identity Mappers,cn=config?cn?one?(objectClass=ds-cfg-identity-mapper)'

syntax_registry.reg_at(
    OpenDSCfgIdentityMapper.oid, [
        '1.3.6.1.4.1.26027.1.1.113', # ds-cfg-identity-mapper
        '1.3.6.1.4.1.26027.1.1.114', # ds-cfg-proxied-authorization-identity-mapper
    ]
)


class OpenDSCfgCertificateMapper(DynamicDNSelectList):
    oid: str = 'OpenDSCfgCertificateMapper-oid'
    desc: str = 'DN of the ds-cfg-certificate-mapper entry'
    ldap_url = 'ldap:///cn=Certificate Mappers,cn=config?cn?one?(objectClass=ds-cfg-certificate-mapper)'

syntax_registry.reg_at(
    OpenDSCfgCertificateMapper.oid, [
        '1.3.6.1.4.1.26027.1.1.262', # ds-cfg-certificate-mapper
    ]
)


class OpenDSCfgKeyManagerProvider(DynamicDNSelectList):
    oid: str = 'OpenDSCfgKeyManagerProvider-oid'
    desc: str = 'DN of the ds-cfg-key-manager-provider entry'
    ldap_url = 'ldap:///cn=Key Manager Providers,cn=config?cn?one?(objectClass=ds-cfg-key-manager-provider)'

syntax_registry.reg_at(
    OpenDSCfgKeyManagerProvider.oid, [
        '1.3.6.1.4.1.26027.1.1.263', # ds-cfg-key-manager-provider
    ]
)


class OpenDSCfgTrustManagerProvider(DynamicDNSelectList):
    oid: str = 'OpenDSCfgTrustManagerProvider-oid'
    desc: str = 'DN of the ds-cfg-trust-manager-provider entry'
    ldap_url = 'ldap:///cn=Trust Manager Providers,cn=config?cn?one?(objectClass=ds-cfg-trust-manager-provider)'

syntax_registry.reg_at(
    OpenDSCfgTrustManagerProvider.oid, [
        '1.3.6.1.4.1.26027.1.1.264', # ds-cfg-trust-manager-provider
    ]
)


class OpenDSCfgSSLClientAuthPolicy(SelectList):
    oid: str = 'OpenDSCfgSSLClientAuthPolicy-oid'
    desc: str = 'Specifies the policy regarding client SSL certificates'
    attr_value_dict: Dict[str, str] = {
        'disabled': 'Client certificate is not requested',
        'optional': 'Client certificate is requested but not required',
        'required': 'Client certificate is required',
    }

syntax_registry.reg_at(
    OpenDSCfgSSLClientAuthPolicy.oid, [
        '1.3.6.1.4.1.26027.1.1.90', # ds-cfg-ssl-client-auth-policy
    ]
)


class OpenDSCfgSNMPSecurityLevel(SelectList):
    oid: str = 'OpenDSCfgSNMPSecurityLevel-oid'
    desc: str = 'Specifies the policy regarding client SSL certificates'
    attr_value_dict: Dict[str, str] = {
        'authnopriv': 'Authentication activated with no privacy.',
        'authpriv': 'Authentication with privacy activated.',
        'noauthnopriv': 'No security mechanisms activated.',
    }

syntax_registry.reg_at(
    OpenDSCfgSNMPSecurityLevel.oid, [
        '1.3.6.1.4.1.26027.1.1.452', # ds-cfg-security-level
    ]
)


class OpenDSCfgInvalidSchemaBehaviour(SelectList):
    oid: str = 'OpenDSCfgInvalidSchemaBehaviour-oid'
    desc: str = 'Specifies how OpenDS behaves in case of schema errors'
    attr_value_dict: Dict[str, str] = {
        'reject': 'reject',
        'default': 'default',
        'accept': 'accept',
        'warn': 'warn',
    }

syntax_registry.reg_at(
    OpenDSCfgInvalidSchemaBehaviour.oid, [
        '1.3.6.1.4.1.26027.1.1.31', # ds-cfg-invalid-attribute-syntax-behavior
        '1.3.6.1.4.1.26027.1.1.88', # ds-cfg-single-structural-objectclass-behavior
    ]
)


class OpenDSCfgEtimeResolution(SelectList):
    oid: str = 'OpenDSCfgEtimeResolution-oid'
    desc: str = 'Specifies the resolution to use for operation elapsed processing time (etime) measurements.'
    attr_value_dict: Dict[str, str] = {
        'milliseconds': 'milliseconds',
        'nanoseconds': 'nanoseconds',
    }

syntax_registry.reg_at(
    OpenDSCfgEtimeResolution.oid, [
        '1.3.6.1.4.1.26027.1.1.442', # ds-cfg-etime-resolution
    ]
)


class OpenDSCfgWritabilityMode(SelectList):
    oid: str = 'OpenDSCfgWritabilityMode-oid'
    desc: str = 'Specifies the kinds of write operations the Directory Server can process.'
    attr_value_dict: Dict[str, str] = {
        'disabled': 'all write operations are rejected',
        'enabled': 'all write operations are processed',
        'internal-only': 'write operations requested as internal/sync operations are processed',
    }

syntax_registry.reg_at(
    OpenDSCfgWritabilityMode.oid, [
        '1.3.6.1.4.1.26027.1.1.123', # ds-cfg-writability-mode
    ]
)


class OpenDSCfgCertificateValidationPolicy(SelectList):
    oid: str = 'OpenDSCfgCertificateValidationPolicy-oid'
    desc: str = 'Specifies the way client certs are checked in user entry.'
    attr_value_dict: Dict[str, str] = {
        'always': u"Always require matching peer certificate in user's entry",
        'ifpresent': u"Require one matching certificate if attribute exists in user's entry",
        'never': u"Peer certificate is not checked in user's entry at all",
    }

syntax_registry.reg_at(
    OpenDSCfgCertificateValidationPolicy.oid, [
        '1.3.6.1.4.1.26027.1.1.16', # ds-cfg-certificate-validation-policy
    ]
)


class OpenDSCfgAccountStatusNotificationType(SelectList):
    oid: str = 'OpenDSCfgAccountStatusNotificationType-oid'
    desc: str = 'Specifies when the generate a notification about account status'
    attr_value_dict: Dict[str, str] = {
        'account-disabled': 'User account has been disabled by an administrator',
        'account-enabled': 'User account has been enabled by an administrator',
        'account-expired': 'User authentication has failed because the account has expired',
        'account-idle-locked': 'User account has been locked because it was idle for too long',
        'account-permanently-locked': 'User account has been permanently locked after too many failed attempts',
        'account-reset-locked': 'User account has been locked, because the password had been reset by an administrator but not changed by the User within the required interval',
        'account-temporarily-locked': 'User account has been temporarily locked after too many failed attempts',
        'account-unlocked': 'User account has been unlocked by an administrator',
        'password-changed': 'User changes his/her own password',
        'password-expired': 'User authentication has failed because the password has expired',
        'password-expiring': u"Password expiration warning is encountered for user's password for the first time.",
        'password-reset': u"User's password was reset by an administrator.",
    }

syntax_registry.reg_at(
    OpenDSCfgAccountStatusNotificationType.oid, [
        '1.3.6.1.4.1.26027.1.1.238', # ds-cfg-account-status-notification-type
    ]
)


class OpenDSCfgSslProtocol(SelectList):
    oid: str = 'OpenDSCfgSslProtocol-oid'
    desc: str = 'Specifies the SSL/TLS protocols supported.'
    attr_value_dict: Dict[str, str] = {
        'SSL': 'any version of SSL',
        'SSLv2': 'SSL version 2 or higher',
        'SSLv3': 'SSL version 3',
        'TLS': 'any version of TLS',
        'TLSv1': 'TLS version 1.0 (RFC 2246)',
        'TLSv1.1': 'TLS version 1.1 (RFC 4346)',
    }

syntax_registry.reg_at(
    OpenDSCfgSslProtocol.oid, [
        '1.3.6.1.4.1.26027.1.1.391', # ds-cfg-ssl-protocol
    ]
)


class OpenDSCfgSslCipherSuite(SelectList):
    oid: str = 'OpenDSCfgSslCipherSuite-oid'
    desc: str = 'Specifies the used cipher suites.'
    attr_value_dict: Dict[str, str] = {
        'SSL_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA': 'SSL_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
        'SSL_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA': 'SSL_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
        'SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA': 'SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
        'SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA': 'SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
        'SSL_DHE_DSS_WITH_DES_CBC_SHA': 'SSL_DHE_DSS_WITH_DES_CBC_SHA',
        'SSL_DHE_DSS_WITH_RC4_128_SHA': 'SSL_DHE_DSS_WITH_RC4_128_SHA',
        'SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA': 'SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
        'SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA': 'SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
        'SSL_DHE_RSA_WITH_DES_CBC_SHA': 'SSL_DHE_RSA_WITH_DES_CBC_SHA',
        'SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA': 'SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
        'SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA': 'SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA',
        'SSL_DH_DSS_WITH_DES_CBC_SHA': 'SSL_DH_DSS_WITH_DES_CBC_SHA',
        'SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA': 'SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
        'SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA': 'SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA',
        'SSL_DH_RSA_WITH_DES_CBC_SHA': 'SSL_DH_RSA_WITH_DES_CBC_SHA',
        'SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA': 'SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
        'SSL_DH_anon_EXPORT_WITH_RC4_40_MD5': 'SSL_DH_anon_EXPORT_WITH_RC4_40_MD5',
        'SSL_DH_anon_WITH_3DES_EDE_CBC_SHA': 'SSL_DH_anon_WITH_3DES_EDE_CBC_SHA',
        'SSL_DH_anon_WITH_DES_CBC_SHA': 'SSL_DH_anon_WITH_DES_CBC_SHA',
        'SSL_DH_anon_WITH_RC4_128_MD5': 'SSL_DH_anon_WITH_RC4_128_MD5',
        'SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA': 'SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA',
        'SSL_FORTEZZA_DMS_WITH_NULL_SHA': 'SSL_FORTEZZA_DMS_WITH_NULL_SHA',
        'SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA': 'SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA',
        'SSL_RSA_EXPORT1024_WITH_RC4_56_SHA': 'SSL_RSA_EXPORT1024_WITH_RC4_56_SHA',
        'SSL_RSA_EXPORT_WITH_DES40_CBC_SHA': 'SSL_RSA_EXPORT_WITH_DES40_CBC_SHA',
        'SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5': 'SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
        'SSL_RSA_EXPORT_WITH_RC4_40_MD5': 'SSL_RSA_EXPORT_WITH_RC4_40_MD5',
        'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA': 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
        'SSL_RSA_FIPS_WITH_DES_CBC_SHA': 'SSL_RSA_FIPS_WITH_DES_CBC_SHA',
        'SSL_RSA_WITH_3DES_EDE_CBC_SHA': 'SSL_RSA_WITH_3DES_EDE_CBC_SHA',
        'SSL_RSA_WITH_DES_CBC_SHA': 'SSL_RSA_WITH_DES_CBC_SHA',
        'SSL_RSA_WITH_IDEA_CBC_SHA': 'SSL_RSA_WITH_IDEA_CBC_SHA',
        'SSL_RSA_WITH_NULL_MD5': 'SSL_RSA_WITH_NULL_MD5',
        'SSL_RSA_WITH_NULL_SHA': 'SSL_RSA_WITH_NULL_SHA',
        'SSL_RSA_WITH_RC4_128_MD5': 'SSL_RSA_WITH_RC4_128_MD5',
        'SSL_RSA_WITH_RC4_128_SHA': 'SSL_RSA_WITH_RC4_128_SHA',
        'TLS_DHE_DSS_WITH_AES_128_CBC_SHA': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
        'TLS_DHE_DSS_WITH_AES_256_CBC_SHA': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
        'TLS_DHE_RSA_WITH_AES_128_CBC_SHA': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_DHE_RSA_WITH_AES_256_CBC_SHA': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
        'TLS_DH_anon_WITH_AES_128_CBC_SHA': 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
        'TLS_DH_anon_WITH_AES_256_CBC_SHA': 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
        'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
        'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
        'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
        'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
        'TLS_KRB5_EXPORT_WITH_RC4_40_MD5': 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
        'TLS_KRB5_EXPORT_WITH_RC4_40_SHA': 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
        'TLS_KRB5_WITH_3DES_EDE_CBC_MD5': 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
        'TLS_KRB5_WITH_3DES_EDE_CBC_SHA': 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
        'TLS_KRB5_WITH_DES_CBC_MD5': 'TLS_KRB5_WITH_DES_CBC_MD5',
        'TLS_KRB5_WITH_DES_CBC_SHA': 'TLS_KRB5_WITH_DES_CBC_SHA',
        'TLS_KRB5_WITH_IDEA_CBC_MD5': 'TLS_KRB5_WITH_IDEA_CBC_MD5',
        'TLS_KRB5_WITH_IDEA_CBC_SHA': 'TLS_KRB5_WITH_IDEA_CBC_SHA',
        'TLS_KRB5_WITH_RC4_128_MD5': 'TLS_KRB5_WITH_RC4_128_MD5',
        'TLS_KRB5_WITH_RC4_128_SHA': 'TLS_KRB5_WITH_RC4_128_SHA',
        'TLS_RSA_WITH_AES_128_CBC_SHA': 'TLS_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_AES_256_CBC_SHA': 'TLS_RSA_WITH_AES_256_CBC_SHA',
    }

syntax_registry.reg_at(
    OpenDSCfgSslCipherSuite.oid, [
        '1.3.6.1.4.1.26027.1.1.392', # ds-cfg-ssl-cipher-suite
    ]
)


class OpenDSCfgPrivilege(SelectList):
    oid: str = 'OpenDSCfgPrivilege-oid'
    desc: str = 'Specifies the name of a privilege that should not be evaluated by the server.'
    attr_value_dict: Dict[str, str] = {
        'backend-backup': 'Request backup tasks',
        'backend-restore': 'Request restore tasks',
        'bypass-acl': 'Bypass access control checks',
        'bypass-lockdown': 'Bypass server lockdown mode',
        'cancel-request': 'Cancel operations of other client connections',
        'config-read': 'Read server configuration',
        'config-write': 'Update the server configuration',
        'data-sync': 'Participate in data synchronization',
        'disconnect-client': 'Terminate other client connections',
        'jmx-notify': 'Subscribe to receive JMX notifications',
        'jmx-read': 'Perform JMX read operations',
        'jmx-write': 'Perform JMX write operations',
        'ldif-export': 'Request LDIF export tasks',
        'ldif-import': 'Request LDIF import tasks',
        'modify-acl':u"Modify the server's access control configuration",
        'password-reset': 'Reset user passwords',
        'privilege-change': 'Make changes to specific root privileges and user privileges',
        'proxied-auth': 'Use proxied authorization control or SASL authz ID',
        'server-lockdown': 'Lockdown a server',
        'server-restart': 'Request server to perform an in-core restart',
        'server-shutdown': 'Request server shut down',
        'subentry-write': 'Perform write ops on LDAP subentries',
        'unindexed-search': 'Request unindexed searches',
        'update-schema': 'Change server schema',
        'changelog-read': 'Read change log backend',
        'monitor-read': 'Read monitoring backend',
    }


syntax_registry.reg_at(
    OpenDSCfgPrivilege.oid, [
        '1.3.6.1.4.1.26027.1.1.261', # ds-cfg-default-root-privilege-name
        '1.3.6.1.4.1.26027.1.1.387', # ds-cfg-disabled-privilege
        '1.3.6.1.4.1.26027.1.1.260', # ds-privilege-name
    ]
)


class OpenDSCfgTimeInterval(DirectoryString):
    oid: str = 'OpenDSCfgTimeInterval-oid'
    desc: str = 'A time interval consisting of integer value and time unit'
    pattern = re.compile('^[0-9]+ (seconds|minutes|hours|days)$')

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
    oid: str = 'OpenDSSyncHist-oid'
    desc: str = 'List of modifications'

    def display(self, valueindex=0, commandbutton=False) -> str:
        try:
            mod_attr_type, mod_number, mod_type, mod_value = self._av.split(':', 3)
        except ValueError:
            return OctetString.display(self, valueindex, commandbutton)
        first_str = self._app.form.utf2display(
            ':'.join((mod_attr_type, mod_number, mod_type)).decode(self._app.ls.charset)
        )
        if no_humanreadable_attr(self._schema, mod_attr_type):
            mod_value_html = mod_value.hex().upper()
        else:
            mod_value_html = self._app.form.utf2display(mod_value.decode(self._app.ls.charset))
        return ':<br>'.join((first_str, mod_value_html))

syntax_registry.reg_at(
    OpenDSSyncHist.oid, [
        '1.3.6.1.4.1.26027.1.1.119', # ds-sync-hist
    ]
)


class OpenDSdsCfgAlternatebindDn(BindDN):
    oid: str = 'OpenDSdsCfgAlternatebindDn-oid'
    desc: str = 'OpenDS/OpenDJ alternative bind DN'

    def form_value(self) -> str:
        if not self._av:
            return ''
        try:
            dn_obj = DNObj(self.av_u)
        except ldap0.DECODING_ERROR:
            return BindDN.form_value(self)
        new_rdn = DNObj(tuple([
            (
                rdn_attr,
                rdn_value[0] or self._entry.get(rdn_attr, [''])[0],
            )
            for rdn_attr, rdn_value in dn_obj.rdn_attrs().items()
        ]))
        return str(new_rdn+dn_obj.parent())

syntax_registry.reg_at(
    OpenDSdsCfgAlternatebindDn.oid, [
        '1.3.6.1.4.1.26027.1.1.13', # ds-cfg-alternate-bind-dn
    ]
)


# cn=changelog
#------------------------

class ChangeLogChanges(MultilineText):
    oid: str = 'ChangeLogChanges-oid'
    desc: str = 'a set of changes to apply to an entry'
    lineSep = b'\n'
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
