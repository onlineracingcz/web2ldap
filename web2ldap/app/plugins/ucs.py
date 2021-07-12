# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for Univention Corporate Server
"""

import bz2
import re

from ..schema.syntaxes import (
    Binary,
    RFC822Address,
    DirectoryString,
    DistinguishedName,
    DynamicDNSelectList,
    MultilineText,
    XmlValue,
    syntax_registry,
)
from .msperson import DateOfBirth


class UniventionObjectType(DirectoryString):
    oid: str = 'UniventionObjectType-oid'
    desc: str = 'Type of UCS object'
    pattern = re.compile('^[a-z_]+/[a-z_]+$')

syntax_registry.reg_at(
    UniventionObjectType.oid, [
        '1.3.6.1.4.1.10176.1003.1', # univentionObjectType
    ]
)


class UniventionPolicyReference(DynamicDNSelectList):
    oid: str = 'UniventionPolicyReference-oid'
    desc: str = 'DN of the univentionPolicy entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=univentionPolicy)'

syntax_registry.reg_at(
    UniventionPolicyReference.oid, [
        '1.3.6.1.4.1.10176.1000', # univentionPolicyReference
    ]
)


syntax_registry.reg_at(
    DateOfBirth.oid, [
        '1.3.6.1.4.1.10176.99', # univentionBirthday
    ]
)


syntax_registry.reg_at(
    RFC822Address.oid, [
        '1.3.6.1.4.1.10176.1010.1.1', # mailPrimaryAddress
        '1.3.6.1.4.1.10176.1010.1.100', # univentionMailMember
    ]
)


syntax_registry.reg_at(
    DistinguishedName.oid, [
        '1.3.6.1.4.1.10176.500.1.5', # univentionDnsForwardZone
        '1.3.6.1.4.1.10176.500.1.6', # univentionDnsReverseZone
        '1.3.6.1.4.1.10176.1000.11.1.2', # univentionNetworkLink
        '1.3.6.1.4.1.10176.4200.4.2', # enabledServiceProviderIdentifierGroup
    ]
)


syntax_registry.reg_at(
    XmlValue.oid, [
        '1.3.6.1.4.1.10176.4200.1.14', # serviceProviderMetadata
    ]
)


class UniventionLDAPACLData(Binary, MultilineText):
    oid: str = 'UniventionLDAPACLData-oid'
    desc: str = 'bzip2-ed LDAP ACL data in Univention'

    def display(self, vidx, links) -> str:
        attr_value = bz2.decompress(self._av)
        attr_value_u = self._app.ls.uc_decode(attr_value)[0]
        lines = [
            self._app.form.s2d(l, tab_identiation='    ')
            for l in self._split_lines(attr_value_u)
        ]
        return '<p>%d bytes <em>BZ2</em> data contains %d chars:</p><pre>%s</pre>' % (
            len(self._av),
            len(attr_value_u),
            '<br>'.join(lines),
        )

syntax_registry.reg_at(
    UniventionLDAPACLData.oid, [
        '1.3.6.1.4.1.10176.4202.1.22', # univentionLDAPACLData
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
