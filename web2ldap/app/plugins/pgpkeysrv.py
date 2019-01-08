# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for PGP key server
"""

from __future__ import absolute_import

import re

from web2ldap.app.schema.syntaxes import \
    DirectoryString, \
    GeneralizedTime, \
    PreformattedMultilineText, \
    DynamicValueSelectList, \
    syntax_registry


syntax_registry.registerAttrType(
    GeneralizedTime.oid, [
        '1.3.6.1.4.1.3401.8.2.17', # pgpKeyCreateTime
        '1.3.6.1.4.1.3401.8.2.22', # pgpKeyExpireTime
    ]
)


class PgpKey(PreformattedMultilineText):
    oid = 'PgpKey-oid'
    desc = 'PGP key'
    reObj = re.compile(
        '^-----BEGIN PGP PUBLIC KEY BLOCK-----[a-zA-Z0-9.: ()+/ =\n-]+-----END PGP PUBLIC KEY BLOCK-----$',
        re.S+re.M,
    )
    lineSep = '\n'
    mimeType = 'application/pgp-keys'
    cols = 64

syntax_registry.registerAttrType(
    PgpKey.oid, [
        '1.3.6.1.4.1.3401.8.2.11', # pgpKey
    ]
)


class PgpCertID(DirectoryString):
    oid = 'PgpCertID-oid'
    desc = 'PGP Cert ID'
    reObj = re.compile('^[a-fA-F0-9]{16}$')

syntax_registry.registerAttrType(
    PgpCertID.oid, [
        '1.3.6.1.4.1.3401.8.2.12', # pgpCertID
    ]
)


class OtherPgpCertID(DynamicValueSelectList, PgpCertID):
    oid = 'OtherPgpCertID-oid'
    ldap_url = 'ldap:///_?pgpCertID,pgpCertID?sub?(objectClass=pgpKeyInfo)'

    def _validate(self, attrValue):
        return PgpCertID._validate(self, attrValue)

syntax_registry.registerAttrType(
    OtherPgpCertID.oid, [
        '1.3.6.1.4.1.3401.8.2.18', # pgpSignerID
    ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
