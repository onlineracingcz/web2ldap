# -*- coding: ascii -*-
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
    PreformattedMultilineText,
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
    desc: str = 'DN of referenced univentionPolicy entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=univentionPolicy)'

syntax_registry.reg_at(
    UniventionPolicyReference.oid, [
        '1.3.6.1.4.1.10176.1000', # univentionPolicyReference
    ]
)


class EntryDNUniventionPolicy(DistinguishedName):
    oid: str = 'EntryDNUniventionPolicy-oid'
    desc: str = 'entryDN of an univentionPolicy entry'
    ref_attrs = (
        (
            'univentionPolicyReference', 'Used by', None,
            'Search all entries referencing this policy.'
        ),
    )

syntax_registry.reg_at(
    EntryDNUniventionPolicy.oid, [
        '1.3.6.1.1.20', # entryDN
        '1.3.6.1.4.1.4203.666.1.33', # entryDN (legacy)
    ],
    structural_oc_oids=[
        '1.3.6.1.4.1.10176.1000.2.2.1', # univentionPolicy
        '1.3.6.1.4.1.10176.1000.308.2.1', # umcPolicy
    ],
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
        '1.3.6.1.4.1.10176.1000.308.1.1', # umcPolicyGrantedOperationSet
    ]
)


syntax_registry.reg_at(
    XmlValue.oid, [
        '1.3.6.1.4.1.10176.4200.1.14', # serviceProviderMetadata
    ]
)


class UniventionLDAPACLData(PreformattedMultilineText):
    oid: str = 'UniventionLDAPACLData-oid'
    desc: str = 'bzip2-ed LDAP ACL data in Univention'

    def sanitize(self, attr_value: bytes) -> bytes:
        return bz2.compress(PreformattedMultilineText.sanitize(self, attr_value))

    def form_value(self) -> str:
        splitted_lines = [
            self._app.ls.uc_decode(line_b)[0]
            for line_b in self._split_lines(bz2.decompress(self._av) or b'')
        ]
        return '\r\n'.join(splitted_lines)

    def validate(self, attr_value: bytes):
        Binary.validate(self, bz2.decompress(attr_value))

    def _split_lines(self, value):
        return bz2.decompress(self._av).split(b'\n')

    def display(self, vidx, links) -> str:
        return PreformattedMultilineText.display(self, vidx, links)

syntax_registry.reg_at(
    UniventionLDAPACLData.oid, [
        '1.3.6.1.4.1.10176.4202.1.22', # univentionLDAPACLData
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
