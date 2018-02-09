# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for
GSER-based LDAP syntaxes defined in
http://tools.ietf.org/html/rfc4523

At this time this is mainly a stub module.
Currently untested!
"""

from __future__ import absolute_import

import mspki.util

from w2lapp.schema.syntaxes import ASN1Object,Binary,GSER,syntax_registry

from ldap0.dn import explode_dn


class AttributeCertificate(Binary):
  oid = '1.3.6.1.4.1.4203.666.11.10.2.1'
  desc = 'X.509 Attribute Certificate'
  mimeType = 'application/pkix-attr-cert'
  fileExt = 'cer'


class CertificateSimpleClass(Binary):
  oid = 'CertificateSimpleClass-oid'
  desc = 'X.509 Certificate'
  mimeType = 'application/pkix-cert'
  fileExt = 'cer'

  def sanitizeInput(self,attrValue):
    try:
      return mspki.util.pem2der(attrValue)
    except (ValueError,IndexError):
      return attrValue

  def getMimeType(self):
    if self._form.browser_type in ['Mozilla','Opera']:
      return 'application/x-x509-email-cert'
    return self.mimeType

  def displayValue(self,valueindex=0,commandbutton=0):
    return '%d bytes | %s' % (
      len(self.attrValue),
      self._form.applAnchor(
        'read','View/Load',self._sid,
        [
          ('dn',self._dn),
          ('read_attr',self.attrType),
          ('read_attrindex',str(valueindex)),
          ('read_attrmode','view'),
        ]
      )
    )


try:
  import M2Crypto
except ImportError:

  class Certificate(CertificateSimpleClass):
    oid = '1.3.6.1.4.1.1466.115.121.1.8'

else:

  class CertificateM2Class(CertificateSimpleClass):
    oid = 'CertificateM2Class-oid'
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

    def displayValue(self,valueindex=0,commandbutton=0):
      links_html = CertificateSimpleClass.displayValue(self,valueindex,commandbutton)
      try:
        x509 = M2Crypto.X509.load_cert_string(self.attrValue,M2Crypto.X509.FORMAT_DER)
      except M2Crypto.X509.X509Error:
        cert_html = ''
      else:
        cert_issuer_dn = ','.join(
          explode_dn(x509.get_issuer().as_text(flags=M2Crypto.m2.XN_FLAG_RFC2253))
        ).decode('utf-8')
        cert_subject_dn = ','.join(
          explode_dn(x509.get_subject().as_text(flags=M2Crypto.m2.XN_FLAG_RFC2253))
        ).decode('utf-8')
        cert_serial_number = int(x509.get_serial_number())
        try:
          cert_not_before = x509.get_not_before().get_datetime()
        except (ValueError,NameError):
          cert_not_before = 'ValueError'
        else:
          cert_not_before = cert_not_before.strftime('%Y-%m-%dT%H-%M-%S %Z')
        try:
          cert_not_after = x509.get_not_after().get_datetime()
        except (ValueError,NameError):
          cert_not_after = 'ValueError'
        else:
          cert_not_after = cert_not_after.strftime('%Y-%m-%dT%H-%M-%S %Z')
        cert_html = self.cert_display_template.format(
          cert_issuer_dn = self._form.utf2display(cert_issuer_dn),
          cert_subject_dn = self._form.utf2display(cert_subject_dn),
          cert_serial_number_dec = str(cert_serial_number),
          cert_serial_number_hex = hex(cert_serial_number),
          cert_not_before = cert_not_before,
          cert_not_after = cert_not_after,
        )
      return ''.join((cert_html,links_html))

  class Certificate(CertificateM2Class):
    oid = '1.3.6.1.4.1.1466.115.121.1.8'


class CACertificate(Certificate):
  oid = 'CACertificate-oid'
  desc = 'X.509 CA Certificate'
  mimeType = 'application/x-x509-ca-cert'

  def getMimeType(self):
    return self.mimeType


class CertificateList(CertificateSimpleClass):
  oid = '1.3.6.1.4.1.1466.115.121.1.9'
  desc = 'Certificate Revocation List'
  mimeType = 'application/pkix-crl'
  fileExt = 'crl'

  def getMimeType(self):
    if self._form.browser_type in ['Mozilla','Opera']:
      return 'application/x-pkcs7-crl'
    return self.mimeType


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

syntax_registry.registerAttrType(
  Certificate.oid,[
    '2.5.4.36', # userCertificate
    'userCertificate','userCertificate;binary',
  ]
)

syntax_registry.registerAttrType(
  CACertificate.oid,[
    '2.5.4.37', # cACertificate
    'cACertificate','cACertificate;binary',
  ]
)

syntax_registry.registerAttrType(
  CertificateList.oid,[
    '2.5.4.38', # authorityRevocationList
    '2.5.4.39', # certificateRevocationList
    '2.5.4.53', # deltaRevocationList
    'authorityRevocationList','authorityRevocationList;binary',
    'certificateRevocationList','certificateRevocationList;binary',
    'deltaRevocationList','deltaRevocationList;binary',
  ]
)


# Register all syntax classes in this module
for symbol_name in dir():
  syntax_registry.registerSyntaxClass(eval(symbol_name))
