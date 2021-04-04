# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for PGP key server
"""

import re

from web2ldap.app.schema.syntaxes import \
    DirectoryString, \
    GeneralizedTime, \
    PreformattedMultilineText, \
    DynamicValueSelectList, \
    syntax_registry


syntax_registry.reg_at(
    GeneralizedTime.oid, [
        '1.3.6.1.4.1.3401.8.2.17', # pgpKeyCreateTime
        '1.3.6.1.4.1.3401.8.2.22', # pgpKeyExpireTime
    ]
)


class PgpKey(PreformattedMultilineText):
    oid: str = 'PgpKey-oid'
    desc: str = 'PGP key'
    pattern = re.compile(
        '^-----BEGIN PGP PUBLIC KEY BLOCK-----[a-zA-Z0-9.: ()+/ =\n-]+-----END PGP PUBLIC KEY BLOCK-----$',
        re.S+re.M,
    )
    lineSep = b'\n'
    mime_type = 'application/pgp-keys'
    cols = 64

syntax_registry.reg_at(
    PgpKey.oid, [
        '1.3.6.1.4.1.3401.8.2.11', # pgpKey
    ]
)


class PgpCertID(DirectoryString):
    oid: str = 'PgpCertID-oid'
    desc: str = 'PGP Cert ID'
    pattern = re.compile('^[a-fA-F0-9]{16}$')

syntax_registry.reg_at(
    PgpCertID.oid, [
        '1.3.6.1.4.1.3401.8.2.12', # pgpCertID
    ]
)


class OtherPgpCertID(DynamicValueSelectList, PgpCertID):
    oid: str = 'OtherPgpCertID-oid'
    ldap_url = 'ldap:///_?pgpCertID,pgpCertID?sub?(objectClass=pgpKeyInfo)'

    def _validate(self, attrValue: bytes) -> bool:
        return PgpCertID._validate(self, attrValue)

syntax_registry.reg_at(
    OtherPgpCertID.oid, [
        '1.3.6.1.4.1.3401.8.2.18', # pgpSignerID
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
