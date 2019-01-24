# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for X.509 cert/CRL schema by DAASI

See also:
http://tools.ietf.org/draft/draft-ietf-pkix-ldap-pkc-schema
"""

from __future__ import absolute_import

from ldap0.filter import escape_filter_chars

from web2ldap.app.schema.syntaxes import DumpASN1CfgOID
from web2ldap.app.schema.syntaxes import \
    DistinguishedName, \
    SelectList, \
    syntax_registry


# This overrides the eventually configured OctetString syntax
# and treats these attribute types as not human-readable and
# not editable binary blobs
syntax_registry.reg_at(
    DumpASN1CfgOID.oid, [
        '1.3.6.1.4.1.10126.1.5.3.3', # x509signatureAlgorithm
        '1.3.6.1.4.1.10126.1.5.3.8', # x509subjectPublicKeyInfoAlgorithm
        '1.3.6.1.4.1.10126.1.5.3.16', # x509policyInformationIdentifier
        '1.3.6.1.4.1.10126.1.5.3.22', # x509subjectRegisteredID
        '1.3.6.1.4.1.10126.1.5.3.28', # x509issuerRegisteredID
        '1.3.6.1.4.1.10126.1.5.3.30', # x509extKeyUsage
    ]
)


class PkcX509Issuer(DistinguishedName):
    oid = 'PkcX509Issuer-oid'

    def _additional_links(self):
        return [
            self._app.anchor(
                'search', 'Issuer',
                [
                    ('dn', self._app.naming_context),
                    (
                        'filterstr',
                        u'(&(objectClass=x509caCertificate)(x509subject=%s))' % (
                            escape_filter_chars(self.av_u),
                        )
                    ),
                ],
                title=u'Search for issuer entries',
            ),
        ]

syntax_registry.reg_at(
    PkcX509Issuer.oid, [
        '1.3.6.1.4.1.10126.1.5.3.4', # x509issuer
    ]
)


class X509KeyUsage(SelectList):
    oid = 'X509KeyUsage-oid'
    desc = 'Key usage extension'
    attr_value_dict = {
        u'digitalSignature': u'digitalSignature',
        u'nonRepudiation': u'nonRepudiation',
        u'keyEncipherment': u'keyEncipherment',
        u'dataEncipherment': u'dataEncipherment',
        u'keyAgreement': u'keyAgreement',
        u'keyCertSign': u'keyCertSign',
        u'cRLSign': u'cRLSign',
        u'encipherOnly': u'encipherOnly',
        u'decipherOnly': u'decipherOnly',
    }

syntax_registry.reg_at(
    X509KeyUsage.oid, [
        '1.3.6.1.4.1.10126.1.5.3.15', # x509keyUsage
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
