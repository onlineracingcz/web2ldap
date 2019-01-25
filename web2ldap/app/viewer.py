# -*- coding: utf-8 -*-
"""
web2ldap.app.viewer: handler classes for displaying binary attributes

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import web2ldapcnf

from web2ldap.log import logger, log_exception
import web2ldap.web.forms
import web2ldap.web.helper
import web2ldap.app.gui
import web2ldap.app.core
from web2ldap.mspki import x509v3, asn1helper, asn1types

viewer_func = {}


CertificateParserError = ValueError

# Get OID dictionary
try:
    asn1helper.oids = asn1helper.ParseCfg(web2ldapcnf.dumpasn1cfg)
except IOError:
    asn1helper.oids = {}


class CRLDisplayer(x509v3.CRL):
    """
    Class for display HTML representation of X509 CRL
    """

    def html(self, app, ldap_attrtype, ldap_attrindex):
        """
        Display a CRL in HTML with all details
        """
        asn1types.url_prefix = '%s/urlredirect/%s?' % (app.form.script_name, app.sid)
        asn1types.url_target = 'web2ldap_certurl'
        app.outf.write(
            web2ldap.app.gui.command_div(
                [
                    app.anchor(
                        'read', 'Install',
                        [
                            ('dn', app.dn),
                            ('read_attr', ldap_attrtype),
                            ('read_attrmode', 'load'),
                            ('read_attrindex', str(ldap_attrindex)),
                        ],
                    ),
                    app.anchor(
                        'read', 'Save to disk',
                        [
                            ('dn', app.dn),
                            ('read_attr', ldap_attrtype),
                            ('read_attrmode', 'load'),
                            ('read_attrmimetype', 'application/octet-stream'),
                            ('read_attrindex', str(ldap_attrindex)),
                        ],
                    ),
                ],
            )
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
                        web2ldap.web.forms.escape_html(class_name),
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
                userCertificate, revocationDate, crlEntryExtensions = i
                if crlEntryExtensions is not None:
                    crlEntryExtensions_html = x509v3.htmlize(crlEntryExtensions)
                else:
                    crlEntryExtensions_html = ''
                revokedCertificates_tr_items.append(
                    '<tr><td>%d</td><td>%s</td><td>%s</td></tr>\n' % (
                        userCertificate,
                        revocationDate,
                        crlEntryExtensions_html,
                    )
                )
            revokedCertificates_str = """<table summary="Revoked certificates">
            <tr><th>Serial Number</th><th>Revocation date</th><th>Extensions</th>
            %s
            </table>
            """ % ('\n'.join(revokedCertificates_tr_items))
        else:
            revokedCertificates_str = '<p>No revoked certificates.</p>'
        app.outf.write(
            """
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
                self.issuer().html(asn1helper.oids, app.form.accept_charset),
                self.version(),
                self.thisUpdate(),
                self.nextUpdate(),
                asn1helper.GetOIDDescription(self.signatureAlgorithm(), asn1helper.oids),
                '\n'.join(extensions_html_list),
                len(revokedCertificates),
                revokedCertificates_str,
            )
        )


class CertificateDisplayer(x509v3.Certificate):
    """
    Class for display HTML representation of X509 certificate
    """

    def html(self, app, ldap_attrtype, ldap_attrindex):
        """
        Display a X.509 certificate in HTML with all details
        """
        asn1types.url_prefix = '%s/urlredirect/%s?' % (app.form.script_name, app.sid)
        asn1types.url_target = 'web2ldap_certurl'
        app.outf.write(
            web2ldap.app.gui.command_div(
                [
                    app.anchor(
                        'read', 'Install',
                        [
                            ('dn', app.dn),
                            ('read_attr', ldap_attrtype),
                            ('read_attrmode', 'load'),
                            ('read_attrindex', str(ldap_attrindex)),
                        ],
                    ),
                    app.anchor(
                        'read', 'Save to disk',
                        [
                            ('dn', app.dn),
                            ('read_attr', ldap_attrtype),
                            ('read_attrmode', 'load'),
                            ('read_attrmimetype', 'application/octet-stream'),
                            ('read_attrindex', str(ldap_attrindex)),
                        ],
                    ),
                ],
            )
        )

        # strings containing UTCTime of begin and end of validity period
        notBefore, notAfter = self.validity()

        # Get the extensions as string-keyed dict but with
        # numeric string representation of OIDs
        extensions_html_list = [
            '<dt>%s (%s)</dt><dd>%s</dd>' % (
                e.extnValue.__class__.__name__,
                str(e.extnId),
                x509v3.htmlize(e.extnValue)
            )
            for e in self.extensions()
        ] or ['No extensions.']

        app.outf.write(
            """
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
                self.subject().html(asn1helper.oids, app.form.accept_charset),
                self.issuer().html(asn1helper.oids, app.form.accept_charset),
                self.version(),
                self.serialNumber(),
                notBefore,
                notAfter,
                self.fingerprint('md5'),
                self.fingerprint('sha1'),
                self.fingerprint('sha256'),
                asn1helper.GetOIDDescription(self.signatureAlgorithm(), asn1helper.oids),
                '\n'.join(extensions_html_list),
            )
        )


def display_x509_cert(app, attr, entry, index=None):
    """
    Display a X.509 certificate attribute
    """
    app.outf.write('<h1>%s</h1>' % (attr))
    attr_value_count = len(entry[attr])
    for i in range(attr_value_count):
        if attr_value_count > 1:
            app.outf.write('<h2>%d. / %d</h2>' % (i+1, attr_value_count))
        try:
            CertificateDisplayer(entry[attr][i]).html(
                app, attr, index,
            )
        except CertificateParserError as cert_err:
            log_exception(app.env, app.ls)
            app.outf.write('<p class="ErrorMessage">Error parsing certificate.</p>')
    return # display_x509_cert()


def display_x509_crl(app, attr, entry, index=None):
    """
    Display a CRL attribute
    """
    app.outf.write('<h1>%s</h1>' % (attr))
    attr_value_count = len(entry[attr])
    for i in range(attr_value_count):
        if attr_value_count > 1:
            app.outf.write('<h2>%d. / %d</h2>' % (i+1, attr_value_count))
        try:
            CRLDisplayer(entry[attr][index]).html(
                app, attr, i,
            )
        except CertificateParserError as cert_err:
            log_exception(app.env, app.ls)
            app.outf.write('<p class="ErrorMessage">Error parsing CRL.</p>')
    return # display_x509_crl()


# register viewer functions by syntax OID
viewer_func['1.3.6.1.4.1.1466.115.121.1.8'] = display_x509_cert
viewer_func['CACertificate-oid'] = display_x509_cert
viewer_func['1.3.6.1.4.1.1466.115.121.1.9'] = display_x509_crl
