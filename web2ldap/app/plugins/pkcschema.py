# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for X.509 cert/CRL schema by DAASI

See also:
http://tools.ietf.org/draft/draft-ietf-pkix-ldap-pkc-schema
"""

import ldap0.filter

from web2ldap.app.schema.syntaxes import \
    DistinguishedName, \
    SelectList, \
    syntax_registry


class PkcX509Issuer(DistinguishedName):
    oid: str = 'PkcX509Issuer-oid'

    def _additional_links(self):
        return [
            self._app.anchor(
                'search', 'Issuer',
                [
                    ('dn', str(self._app.naming_context)),
                    (
                        'filterstr',
                        '(&(objectClass=x509caCertificate)(x509subject=%s))' % (
                            ldap0.filter.escape_str(self.av_u),
                        )
                    ),
                ],
                title='Search for issuer entries',
            ),
        ]

syntax_registry.reg_at(
    PkcX509Issuer.oid, [
        '1.3.6.1.4.1.10126.1.5.3.4', # x509issuer
    ]
)


class X509KeyUsage(SelectList):
    oid: str = 'X509KeyUsage-oid'
    desc: str = 'Key usage extension'
    attr_value_dict = {
        'digitalSignature': 'digitalSignature',
        'nonRepudiation': 'nonRepudiation',
        'keyEncipherment': 'keyEncipherment',
        'dataEncipherment': 'dataEncipherment',
        'keyAgreement': 'keyAgreement',
        'keyCertSign': 'keyCertSign',
        'cRLSign': 'cRLSign',
        'encipherOnly': 'encipherOnly',
        'decipherOnly': 'decipherOnly',
    }

syntax_registry.reg_at(
    X509KeyUsage.oid, [
        '1.3.6.1.4.1.10126.1.5.3.15', # x509keyUsage
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
