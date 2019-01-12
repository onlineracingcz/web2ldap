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
    DynamicValueSelectList, \
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


class PkcX509Issuer(DynamicValueSelectList, DistinguishedName):
    oid = 'PkcX509Issuer-oid'
    ldap_url = 'ldap:///_?x509subject,x509subject?sub?(objectClass=x509caCertificate)'

    def _validate(self, attrValue):
        return DistinguishedName._validate(self, attrValue)

    def displayValue(self, valueindex=0, commandbutton=False):
        r = [
            DistinguishedName.displayValue(self, valueindex, commandbutton=0),
        ]
        r.append(self._form.applAnchor(
            'search', '&raquo;', self._sid,
            [
                ('dn', self._determineSearchDN(self._dn, self.lu_obj.dn)),
                (
                    'filterstr',
                    u'(&%s(x509subject=%s))' % (
                        self._determineFilter().decode('utf-8'),
                        escape_filter_chars(self._ls.uc_decode(self.attrValue)[0]),
                    )
                ),
            ],
            title=u'Search for issuer entries',
        ))
        return ' '.join(r)

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
