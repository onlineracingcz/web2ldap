# -*- coding: utf-8 -*-
"""
Special syntax and attribute type registrations for enforcing
standard-compliant behaviour even if current subschema of
a server is errornous or could not be retrieved.
"""

from __future__ import absolute_import

import ldap0.ldapurl

import web2ldap.app.searchform
from web2ldap.app.schema.syntaxes import \
    syntax_registry, \
    Audio, \
    AuthzDN, \
    Binary, \
    Boolean, \
    CountryString, \
    DirectoryString, \
    DistinguishedName, \
    DomainComponent, \
    JPEGImage, \
    LDAPUrl, \
    LDAPUrl, \
    OctetString, \
    OID, \
    PhotoG3Fax, \
    PostalAddress, \
    RFC822Address, \
    Uri, \
    UTCTime


syntax_registry.reg_at(
    OID.oid,
    [
        '1.2.826.0.1050.11.0', 'ogSupportedProfile',
        '1.3.6.1.4.1.1466.101.120.13', 'supportedControl',
        '1.3.6.1.4.1.1466.101.120.7', 'supportedExtension',
        '1.3.6.1.4.1.4203.1.3.5', 'supportedFeatures',
        'supportedCapabilities',
    ]
)

syntax_registry.reg_at(
    RFC822Address.oid,
    [
        '0.9.2342.19200300.100.1.3',    # mail, rfc822Mailbox
        '2.16.840.1.113730.3.1.13',     # mailLocalAddress
        '2.16.840.1.113730.3.1.17',     # mailForwardingAddress
        '2.16.840.1.113730.3.1.30',     # mgrpRFC822MailMember
        '1.3.6.1.4.1.42.2.27.2.1.15',   # rfc822MailMember
        '2.16.840.1.113730.3.1.47',     # mailRoutingAddress
        '1.2.840.113549.1.9.1',         # email, emailAddress, pkcs9email
    ]
)

syntax_registry.reg_at(
    JPEGImage.oid,
    [
        '0.9.2342.19200300.100.1.60', # jpegPhoto
    ]
)

syntax_registry.reg_at(
    Audio.oid,
    [
        '0.9.2342.19200300.100.1.55', # audio
    ]
)

syntax_registry.reg_at(
    PhotoG3Fax.oid,
    [
        '0.9.2342.19200300.100.1.7', # photo
    ]
)

syntax_registry.reg_at(
    Uri.oid, [
        '1.3.6.1.4.1.250.1.57', # labeledURI
    ]
)

syntax_registry.reg_at(
    Boolean.oid, [
        '2.5.18.9', # hasSubordinates
    ]
)

syntax_registry.reg_at(
    PostalAddress.oid, [
        '2.5.4.16',                   # postalAddress
        '2.5.4.26',                   # registeredAddress
        '0.9.2342.19200300.100.1.39', # homePostalAddress
    ]
)

syntax_registry.reg_at(
    LDAPUrl.oid, [
        '2.16.840.1.113730.3.1.34', # ref
    ]
)

syntax_registry.reg_at(
    UTCTime.oid, [
        '2.5.18.1', # createTimestamp
        '2.5.18.2', # modifyTimestamp
        'createtimestamp-oid', # createtimestamp on Netscape DS 4.x
        'modifytimestamp-oid', # modifytimestamp on Netscape DS 4.x
    ]
)

syntax_registry.reg_at(
    CountryString.oid, [
        'c',
        'countryName',
        '2.5.4.6', # c
    ]
)

# Some LDAP servers (e.g. MS AD) declare these attributes with OctetString
# syntax but Binary syntax is more suitable
syntax_registry.reg_at(
    Binary.oid, [
        '2.16.840.1.113730.3.1.216', # userPKCS12
        '2.16.840.1.113730.3.140',   # userSMIMECertificate
    ]
)

syntax_registry.reg_at(
    AuthzDN.oid, [
        '2.5.18.3', # creatorsName
        '2.5.18.4', # modifiersName
    ]
)

syntax_registry.reg_at(
    DomainComponent.oid, [
        '0.9.2342.19200300.100.1.25', # dc (alias domainComponent)
        'dc',
        'domainComponent',
    ]
)


class UserPassword(OctetString, DirectoryString):
    oid = 'UserPassword-oid'

    def displayValue(self, valueindex=0, commandbutton=False):
        try:
            result = DirectoryString.displayValue(self, valueindex, commandbutton)
        except UnicodeDecodeError:
            result = OctetString.displayValue(self, valueindex, commandbutton)
        return result

syntax_registry.reg_at(
    UserPassword.oid, [
        '2.5.4.35', # userPassword
    ]
)


class NamingContexts(DistinguishedName):
    oid = 'NamingContexts-oid'
    desc = 'Naming contexts in rootDSE'
    ldap_url = 'ldap:///cn=cn=config?olcSuffix?one?(objectClass=olcDatabaseConfig)'

    def _config_link(self):
        attr_value_u = self._app.ls.uc_decode(self._av)[0]
        config_context = None
        config_scope_str = None
        config_filter = None
        # Check for OpenLDAP's config context attribute
        try:
            config_context = self._app.ls.uc_decode(self._app.ls.rootDSE['configContext'][0])[0]
        except KeyError:
            # Check for OpenDJ's config context attribute
            try:
                _ = self._app.ls.rootDSE['ds-private-naming-contexts']
            except KeyError:
                pass
            else:
                config_context = u'cn=Backends,cn=config'
                config_filter = u'(&(objectClass=ds-cfg-backend)(ds-cfg-base-dn=%s))' % (attr_value_u)
                config_scope_str = web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL
        else:
            config_filter = u'(&(objectClass=olcDatabaseConfig)(olcSuffix=%s))' % (attr_value_u)
            config_scope_str = web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL
        if config_context and config_scope_str and config_filter:
            return self._app.anchor(
                'search', 'Config',
                (
                    ('dn', config_context),
                    ('scope', config_scope_str),
                    ('filterstr', config_filter),
                ),
                title=u'Search for configuration entry below %s' % (config_context),
            )
        return None

    def _monitor_link(self):
        attr_value_u = self._app.ls.uc_decode(self._av)[0]
        monitor_context = None
        monitor_scope_str = None
        monitor_filter = None
        # Check for OpenLDAP's config context attribute
        try:
            _ = self._app.ls.rootDSE['monitorContext']
        except KeyError:
            # Check for OpenDJ's config context attribute
            try:
                _ = self._app.ls.rootDSE['ds-private-naming-contexts']
            except KeyError:
                pass
            else:
                monitor_context = u'cn=monitor'
                monitor_filter = u'(&(objectClass=ds-backend-monitor-entry)(ds-backend-base-dn=%s))' % (attr_value_u)
                monitor_scope_str = web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL
        else:
            monitor_context = u'cn=Databases,cn=Monitor'
            monitor_filter = u'(&(objectClass=monitoredObject)(namingContexts=%s))' % (attr_value_u)
            monitor_scope_str = web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL
        if monitor_context and monitor_scope_str and monitor_filter:
            return self._app.anchor(
                'search', 'Monitor',
                (
                    ('dn', monitor_context),
                    ('scope', monitor_scope_str),
                    ('filterstr', monitor_filter),
                ),
                title=u'Search for monitoring entry below %s' % (monitor_context),
            )
        return None

    def _additional_links(self):
        attr_value_u = self._app.ls.uc_decode(self._av)[0]
        r = DistinguishedName._additional_links(self)
        r.append(self._app.anchor(
            'search', 'Down',
            (
                ('dn', attr_value_u),
                ('scope', web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
                ('filterstr', u'(objectClass=*)'),
            )
        ))
        r.append(self._app.anchor(
            'dit', 'Tree',
            (
                ('dn', attr_value_u),
            )
        ))
        config_link = self._config_link()
        if config_link:
            r.append(config_link)
        monitor_link = self._monitor_link()
        if monitor_link:
            r.append(monitor_link)
        return r

syntax_registry.reg_at(
    NamingContexts.oid, [
        'namingContexts',
        '1.3.6.1.4.1.1466.101.120.5', # namingContexts
    ]
)


class AltServer(LDAPUrl):
    oid = 'AltServer-oid'
    desc = 'LDAP URIs of alternative server(s)'

    def _command_ldap_url(self, ldap_url):
        ldap_url_obj = ldap0.ldapurl.LDAPUrl(ldapUrl=ldap_url)
        ldap_url_obj.who = self._app.ls.who
        ldap_url_obj.scope = ldap0.ldapurl.LDAP_SCOPE_BASE
        ldap_url_obj.cred = None
        return ldap_url_obj

syntax_registry.reg_at(
    AltServer.oid, [
        'altServer',
        '1.3.6.1.4.1.1466.101.120.6', # altServer
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
