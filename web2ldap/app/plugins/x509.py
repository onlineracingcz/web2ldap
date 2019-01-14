# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for
GSER-based LDAP syntaxes defined in
http://tools.ietf.org/html/rfc4523

At this time this is mainly a stub module.
Currently untested!
"""

from __future__ import absolute_import

import ldap0.dn

import asn1crypto.pem
import asn1crypto.x509
import asn1crypto.crl

from web2ldap.app.schema.syntaxes import ASN1Object, Binary, GSER, syntax_registry


def x509name2ldapdn(x509name, subschema=None):
    dn_list = []
    for rdn in reversed(x509name.chosen):
        rdn_list = []
        for ava in rdn:
            type_oid = ava['type'].dotted.encode('ascii')
            type_name = type_oid
            if subschema is not None:
                try:
                    at_obj = subschema.get_obj(
                        ldap0.schema.models.AttributeType,
                        type_oid,
                        raise_keyerror=True,
                    )
                except (KeyError, IndexError):
                    pass
                else:
                    type_name = at_obj.names[0]
            rdn_list.append((
                type_name,
                ava['value'].native.encode('utf-8'),
                0,
            ))
        dn_list.append(rdn_list)
    return ldap0.dn.dn2str(dn_list).decode('utf-8')
    # end of x509name2ldapdn()


class AttributeCertificate(Binary):
    oid = '1.3.6.1.4.1.4203.666.11.10.2.1'
    desc = 'X.509 Attribute Certificate'
    mimeType = 'application/pkix-attr-cert'
    fileExt = 'cer'


class Certificate(Binary):
    oid = '1.3.6.1.4.1.1466.115.121.1.8'
    desc = 'X.509 Certificate'
    mimeType = 'application/pkix-cert'
    fileExt = 'cer'
    cert_display_template = """
      <dl>
        <dt>Issuer:</dt>
        <dd>{cert_issuer_dn}</dd>
        <dt>Subject</dt>
        <dd>{cert_subject_dn}</dd>
        <dt>Serial No.</dt>
        <dd>{cert_serial_number_dec} ({cert_serial_number_hex})</dd>
        <dt>Validity period</dt>
        <dd>from {cert_not_before} until {cert_not_after}</dd>
      </dl>
      """

    def sanitizeInput(self, attrValue):
        if asn1crypto.pem.detect(attrValue):
            try:
                _, _, attrValue = asn1crypto.pem.unarmor(attrValue, multiple=False)
            except ValueError:
                pass
        return attrValue

    def displayValue(self, valueindex=0, commandbutton=False):
        html = [
            '%d bytes | %s' % (
                len(self.attrValue),
                self._app.anchor(
                    'read', 'View/Load',
                    [
                        ('dn', self._dn),
                        ('read_attr', self.attrType),
                        ('read_attrindex', str(valueindex)),
                        ('read_attrmode', 'view'),
                    ],
                )
            )
        ]
        try:
            x509 = asn1crypto.x509.Certificate.load(self.attrValue)
        except ValueError:
            return ''.join(html)
        html.append(
            self.cert_display_template.format(
                cert_issuer_dn=self._app.form.utf2display(x509name2ldapdn(x509.issuer, self._schema)),
                cert_subject_dn=self._app.form.utf2display(x509name2ldapdn(x509.subject, self._schema)),
                cert_serial_number_dec=str(x509.serial_number),
                cert_serial_number_hex=hex(x509.serial_number),
                cert_not_before=x509['tbs_certificate']['validity']['not_before'].native,
                cert_not_after=x509['tbs_certificate']['validity']['not_after'].native,
            )
        )
        html.append('<p>Extensions</p>')
        html.append('<dl>')
        for ext in x509['tbs_certificate']['extensions']:
            ext_oid = unicode(ext['extn_id'])
            html.append(
                """
                <dt>{ext_crit} {ext_name} {ext_id} </dt>
                <dd>{extn_value}</dd>
                """.format(
                    ext_id=self._app.form.utf2display(ext_oid),
                    ext_name=asn1crypto.x509.ExtensionId._map.get(ext_oid, ext_oid),
                    ext_crit={False:u'', True:u'critical: '}[ext['critical'].native],
                    extn_value=self._app.form.utf2display(unicode(ext['extn_value'].parsed)),
                )
            )
        html.append('</dl>')
        return ''.join(html)


class CACertificate(Certificate):
    oid = 'CACertificate-oid'
    desc = 'X.509 CA Certificate'
    mimeType = 'application/x-x509-ca-cert'

    def getMimeType(self):
        return self.mimeType


class CertificateList(Binary):
    oid = '1.3.6.1.4.1.1466.115.121.1.9'
    desc = 'Certificate Revocation List'
    mimeType = 'application/pkix-crl'
    fileExt = 'crl'
    crl_display_template = """
      <dl>
        <dt>Issuer:</dt>
        <dd>{crl_issuer_dn}</dd>
        <dt>This update</dt>
        <dd>{crl_this_update}</dd>
        <dt>Next update</dt>
        <dd>{crl_next_update}</dd>
      </dl>
      """

    def sanitizeInput(self, attrValue):
        if asn1crypto.pem.detect(attrValue):
            try:
                _, _, attrValue = asn1crypto.pem.unarmor(attrValue, multiple=False)
            except ValueError:
                pass
        return attrValue

    def displayValue(self, valueindex=0, commandbutton=False):
        links_html = '%d bytes | %s' % (
            len(self.attrValue),
            self._app.anchor(
                'read', 'View/Load',
                [
                    ('dn', self._dn),
                    ('read_attr', self.attrType),
                    ('read_attrindex', str(valueindex)),
                    ('read_attrmode', 'view'),
                ],
            )
        )
        try:
            x509 = asn1crypto.crl.CertificateList.load(self.attrValue)
        except ValueError:
            crl_html = ''
        else:
            crl_html = self.crl_display_template.format(
                crl_issuer_dn=self._app.form.utf2display(x509name2ldapdn(x509.issuer, self._schema)),
                crl_this_update=x509['tbs_cert_list']['this_update'].native,
                crl_next_update=x509['tbs_cert_list']['next_update'].native,
            )
        return ''.join((crl_html, links_html))


class CertificatePair(ASN1Object):
    oid = '1.3.6.1.4.1.1466.115.121.1.10'
    desc = 'X.509 Certificate Pair'
    mimeType = 'application/pkix-cert'
    fileExt = 'cer'


class SupportedAlgorithm(ASN1Object):
    oid = '1.3.6.1.4.1.1466.115.121.1.49'
    desc = 'X.509 Supported Algorithm'


class X509CertificateExactAssertion(GSER):
    oid = '1.3.6.1.1.15.1'
    desc = 'X.509 Certificate Exact Assertion'


class X509CertificateAssertion(GSER):
    oid = '1.3.6.1.1.15.2'
    desc = 'X.509 Certificate Assertion'


class X509CertificatePairExactAssertion(GSER):
    oid = '1.3.6.1.1.15.3'
    desc = 'X.509 Certificate Pair Exact Assertion'


class X509CertificatePairAssertion(GSER):
    oid = '1.3.6.1.1.15.4'
    desc = 'X.509 Certificate Pair Assertion'


class X509CertificateListExactAssertion(GSER):
    oid = '1.3.6.1.1.15.5'
    desc = 'X.509 Certificate List Exact Assertion'


class X509CertificateListAssertion(GSER):
    oid = '1.3.6.1.1.15.6'
    desc = 'X.509 Certificate List Assertion'


class X509AlgorithmIdentifier(GSER):
    oid = '1.3.6.1.1.15.7'
    desc = 'X.509 Algorithm Identifier'


# Hard-coded registration of some attribute types

syntax_registry.reg_at(
    Certificate.oid, [
        '2.5.4.36', # userCertificate
        'userCertificate', 'userCertificate;binary',
    ]
)

syntax_registry.reg_at(
    CACertificate.oid, [
        '2.5.4.37', # cACertificate
        'cACertificate', 'cACertificate;binary',
    ]
)

syntax_registry.reg_at(
    CertificateList.oid, [
        '2.5.4.38', # authorityRevocationList
        '2.5.4.39', # certificateRevocationList
        '2.5.4.53', # deltaRevocationList
        'authorityRevocationList', 'authorityRevocationList;binary',
        'certificateRevocationList', 'certificateRevocationList;binary',
        'deltaRevocationList', 'deltaRevocationList;binary',
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
