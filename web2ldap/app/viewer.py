# -*- coding: utf-8 -*-
"""
web2ldap.app.viewer: handler classes for displaying binary attributes

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import binascii

import pyweblib.forms
import pyweblib.helper

import web2ldap.app.gui
import web2ldap.app.core

from web2ldap.mspki.util import is_base64


viewer_func = {}


def DisplayBinaryAttribute(
  sid,outf,form,dn,
  attrtype,
  entry,
  index=None,
  mimetype='application/octet-stream',
  attachment_filename='web2ldap-export.bin'
):
  """Display a binary attribute."""
  if entry[attrtype][index].startswith('{ASN}'):
    value = binascii.unhexlify(entry[attrtype][index][5:])
  else:
    value = entry[attrtype][index]
  # Send HTTP header with appropriate MIME type
  web2ldap.app.gui.Header(
    outf,
    form,
    content_type=mimetype,
    more_headers = [
      ('Content-Disposition','inline; filename=%s' % attachment_filename),
    ]
  )
  # send attribute value
  outf.write(value)


def x509_prep(value):
  """
  This function returns raw DER cert data no matter what mess was stored
  in value before.
  """
  if is_base64(value):
    return value.strip().decode('base64')
  elif value.startswith('{ASN}'):
    return binascii.unhexlify(value[5:])
  else:
    return value


# my own mspki modules
from web2ldap.mspki import x509v3,asn1helper,asn1types

CertificateParserError = ValueError

# Get OID dictionary
try:
  asn1helper.oids = asn1helper.ParseCfg(web2ldap.app.cnf.misc.dumpasn1cfg)
except IOError:
  asn1helper.oids = {}

class PiscesCRLDisplayer(x509v3.CRL):

  def htmlDetailView(self,sid,outf,form,dn,ldap_attrtype,ldap_attrindex):
    """Display a CRL in HTML with all details"""
    asn1types.url_prefix = '%s/urlredirect/%s?' % (form.script_name,sid)
    asn1types.url_target = 'web2ldap_certurl'
    web2ldap.app.gui.CommandTable(
      outf,
      [
        form.applAnchor(
          'read','Install',sid,
          [
            ('dn',dn),
            ('read_attr',ldap_attrtype),
            ('read_attrmode','load'),
            ('read_attrindex',str(ldap_attrindex)),
          ],
        ),
        form.applAnchor(
          'read','Save to disk',sid,
          [
            ('dn',dn),
            ('read_attr',ldap_attrtype),
            ('read_attrmode','load'),
            ('read_attrmimetype','application/octet-stream'),
            ('read_attrindex',str(ldap_attrindex)),
          ],
        ),
      ]
    )
    # Get the extensions as string-keyed dict but with
    # numeric string representation of OIDs
    extensions = self.crlExtensions()
    if extensions:
      extensions_html_list = []
      for e in extensions:
        try:
          class_name = e.extnValue.__class__.__name__
        except AttributeError:
          class_name = repr(type(e))
        extensions_html_list.append(
          '<dt>%s (%s)</dt><dd>%s</dd>' % (
              pyweblib.forms.escapeHTML(class_name),
              str(e.extnId),
              x509v3.htmlize(e.extnValue)
          )
        )
    else:
      extensions_html_list = ['No CRL extensions.']
    # Display a table of revoked certificates
    revokedCertificates = self.revokedCertificates()
    if revokedCertificates:
      revokedCertificates_tr_items = []
      for i in revokedCertificates:
        userCertificate,revocationDate,crlEntryExtensions = i
        if crlEntryExtensions!=None:
          crlEntryExtensions_html = x509v3.htmlize(crlEntryExtensions)
        else:
          crlEntryExtensions_html = ''
        revokedCertificates_tr_items.append(
          '<tr><td>%d</td><td>%s</td><td>%s</td></tr>\n' % (
            userCertificate,revocationDate,crlEntryExtensions_html
          )
        )
      revokedCertificates_str = """<table summary="Revoked certificates">
      <tr><th>Serial Number</th><th>Revocation date</th><th>Extensions</th>
      %s
      </table>
      """ % ('\n'.join(revokedCertificates_tr_items))
    else:
      revokedCertificates_str = '<p>No revoked certificates.</p>'
    outf.write("""
      <h2>X.509 CRL attributes</h2>
      <dl>
        <dt>This CRL was issued by:</dt>
        <dd>%s</dd>
        <dt>CRL Version:</dt>
        <dd>%d</dd>
        <dt>This CRL is valid from %s until %s.</dt>
        <dt>Signature Algorithm:</dt>
        <dd>%s</dd>
      </dl>
      <h2>X.509v3 CRL extensions</h2>
      %s
      <h2>%d revoked certificates</h2>
      %s
""" % (
      self.issuer().html(asn1helper.oids,form.accept_charset),
      self.version(),
      self.thisUpdate(),
      self.nextUpdate(),
      asn1helper.GetOIDDescription(self.signatureAlgorithm(),asn1helper.oids),
      '\n'.join(extensions_html_list),
      len(revokedCertificates),
      revokedCertificates_str,
    ))


class PiscesCertificateDisplayer(x509v3.Certificate):

  def htmlDetailView(self,sid,outf,form,dn,ldap_attrtype,ldap_attrindex):
    """Display a X.509 certificate in HTML with all details"""
    asn1types.url_prefix = '%s/urlredirect/%s?' % (form.script_name,sid)
    asn1types.url_target = 'web2ldap_certurl'
    web2ldap.app.gui.CommandTable(
      outf,
      [
        form.applAnchor(
          'read','Install',sid,
          [
            ('dn',dn),
            ('read_attr',ldap_attrtype),
            ('read_attrmode','load'),
            ('read_attrindex',str(ldap_attrindex)),
          ],
        ),
        form.applAnchor(
          'read','Save to disk',sid,
          [
            ('dn',dn),
            ('read_attr',ldap_attrtype),
            ('read_attrmode','load'),
            ('read_attrmimetype','application/octet-stream'),
            ('read_attrindex',str(ldap_attrindex)),
          ],
        ),
      ]
    )

    # strings containing UTCTime of begin and end of validity period
    notBefore,notAfter=self.validity()

    # Get the extensions as string-keyed dict but with
    # numeric string representation of OIDs
    extensions = self.extensions()
    nsBaseUrl=''
    if extensions:
      extensions_html_list = []
      for e in extensions:
        if e.extnValue.__class__.__name__ == 'nsBaseUrl':
          nsBaseUrl = str(e.extnValue)
        if e.extnValue.__class__.__name__ in [
          'nsCaRevocationUrl','nsRevocationUrl',
          'nsRenewalUrl','nsCaPolicyUrl'
        ]:
          extensions_html_list.append(
            '<dt>%s (%s)</dt><dd>%s</dd>' % (
                e.extnValue.__class__.__name__,
                str(e.extnId),
                e.extnValue.html(nsBaseUrl,hex(self.serialNumber())[2:-1])
            )
          )
        else:
          extensions_html_list.append(
            '<dt>%s (%s)</dt><dd>%s</dd>' % (
                e.extnValue.__class__.__name__,
                str(e.extnId),
                x509v3.htmlize(e.extnValue)
            )
          )
    else:
      extensions_html_list = ['No extensions.']

    outf.write("""
      <h2>X.509 certificate attributes:</h2>
      <dl>
        <dt>This certificate belongs to:</dt>
        <dd>%s</dd>
        <dt>This certificate was issued by:</dt>
        <dd>%s</dd>
        <dt>Certificate Version:</dt>
        <dd>%d</dd>
        <dt>Serial Number:</dt>
        <dd>%s</dd>
        <dt>Validity Period:</dt>
        <dd>
          <dl>
            <dt>not before</dt><dd>%s</dd>
            <dt>not after</dt><dd>%s</dd>
          </dl>
        </dd>
        <dt>Fingerprint:</dt>
        <dd>
          <dl>
            <dt>MD5</dt><dd>%s</dd>
            <dt>SHA-1</dt><dd>%s</dd>
            <dt>SHA-256</dt><dd>%s</dd>
          </dl>
        </dd>
        <dt>Signature Algorithm:</dt>
        <dd>%s</dd>
      </dl>
      <h2>X.509v3 certificate extensions:</h2>
      <dl>
        %s
      </dl>
""" % (
      self.subject().html(asn1helper.oids,form.accept_charset),
      self.issuer().html(asn1helper.oids,form.accept_charset),
      self.version(),
      self.serialNumber(),
      notBefore,
      notAfter,
      self.fingerprint('md5'),
      self.fingerprint('sha1'),
      self.fingerprint('sha256'),
      asn1helper.GetOIDDescription(self.signatureAlgorithm(),asn1helper.oids),
      '\n'.join(extensions_html_list),
    ))

CRLDisplayer = PiscesCRLDisplayer
CertificateDisplayer = PiscesCertificateDisplayer


def DisplayX509Certificate(sid,outf,command,form,dn,attr,entry,index=None):
  """Display a base64-encoded X.509 certificate attribute"""
  outf.write('<h1>%s</h1>' % (unicode(attr,'ascii')))
  attr_value_count = len(entry[attr])
  for i in range(attr_value_count):
    if attr_value_count>1:
      outf.write('<h2>%d. / %d</h2>' % (i+1,attr_value_count))
    try:
      CertificateDisplayer(x509_prep(entry[attr][i])).htmlDetailView(
        sid,outf,form,dn,attr,index,
      )
    except CertificateParserError:
      outf.write('<p class="ErrorMessage">Error parsing certificate.</p>')
  return # DisplayX509Certificate()


def DisplayCRL(sid,outf,command,form,dn,attr,entry,index=None):
  """Display a base64-encoded CRL attribute"""
  outf.write('<h1>%s</h1>' % (unicode(attr,'ascii')))
  attr_value_count = len(entry[attr])
  for i in range(attr_value_count):
    if attr_value_count>1:
      outf.write('<h2>%d. / %d</h2>' % (i+1,attr_value_count))
    try:
      CRLDisplayer(x509_prep(entry[attr][index])).htmlDetailView(
        sid,outf,form,dn,attr,i,
      )
    except CertificateParserError:
      outf.write('<p class="ErrorMessage">Error parsing CRL.</p>')
  return # DisplayCRL()


# register viewer functions by syntax OID
if CertificateDisplayer:
  viewer_func['1.3.6.1.4.1.1466.115.121.1.8'] = DisplayX509Certificate
  viewer_func['CACertificate-oid'] = DisplayX509Certificate
if CRLDisplayer:
  viewer_func['1.3.6.1.4.1.1466.115.121.1.9'] = DisplayCRL
