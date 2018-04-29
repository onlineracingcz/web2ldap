# -*- coding: utf-8 -*-
"""
web2ldap.app.locate: Try to locate a LDAP host with various methods.

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import socket,ldap0

from dns import resolver

from web2ldap.ldaputil.extldapurl import ExtendedLDAPUrl
from ldap0.ldapurl import LDAPUrlExtension,LDAPUrlExtensions

# Modules shipped with web2ldap
import web2ldap.ldaputil.base,web2ldap.ldaputil.dns,web2ldap.app.gui


ldap_hostname_aliases = [
#  'ldap','dsa','x500','ldapdb','nds','openldap'
  'ldap',
]

##############################################################################
# LDAP Service Locator
##############################################################################

LOCATE_NAME_RFC822 = 0
LOCATE_NAME_DCDN   = 1
LOCATE_NAME_DOMAIN = 2

def w2l_Locate(outf,command,form,env):
  """
  Try to locate a LDAP server in DNS by several heuristics
  """

  locate_name = form.getInputValue('locate_name',[''])[0].strip()

  msg_html = ''
  outf_lines = []

  if locate_name:

    # Try to determine the format of the input parameter
    if web2ldap.ldaputil.base.is_dn(locate_name):
      # Use dc-style LDAP DN
      msg_html = 'Input is considered LDAP distinguished name.'
      locate_domain = web2ldap.ldaputil.dns.dcdn2dnsdomain(locate_name)
      locate_name_type = LOCATE_NAME_DCDN
    elif u'@' in locate_name:
      # Use domain part of RFC822 mail address
      msg_html = 'Input is considered e-mail address or user principal name.'
      locate_domain = locate_name.split('@')[-1]
      locate_name_type = LOCATE_NAME_RFC822
    else:
      # Use DNS domain directly
      msg_html = 'Input is considered DNS domain name.'
      locate_domain = locate_name
      locate_name_type = LOCATE_NAME_DOMAIN

    if locate_domain:

      dns_list = locate_domain.lower().split(u'.')

      for dns_index in range(len(dns_list),0,-1):

        dns_name = '.'.join([ label.encode('idna') for label in dns_list[-dns_index:]])
        dns_name_u = '.'.join([ label.decode('idna') for label in dns_name.split('.')])

        search_base = web2ldap.ldaputil.dns.dnsdomain2dcdn(dns_name)
        if dns_name.endswith('de-mail-test.de') or dns_name.endswith('de-mail.de'):
          search_base = ','.join((search_base,'cn=de-mail'))
          lu_extensions = LDAPUrlExtensions({
            'x-saslmech':LDAPUrlExtension(
              critical=0,
              extype='x-saslmech',
              exvalue='EXTERNAL'
            )
          })
        else:
          lu_extensions = None

        outf_lines.append('<h1><em>%s</em></h1><p>Encoded domain name: <strong>%s</strong></p>\n' % (
          form.utf2display(dns_name_u),
          form.utf2display(dns_name.decode('ascii')),
        ))

        ldap_srv_results = []
        for url_scheme in ('ldap','ldaps'):
            # Search for a SRV RR of dns_name
            srv_prefix = '_%s._tcp' % (url_scheme)
            try:
              dns_result = web2ldap.ldaputil.dns.ldapSRV(dns_name,srv_prefix=srv_prefix)
            except (
              resolver.NoAnswer,
              resolver.NoNameservers,
              resolver.NotAbsolute,
              resolver.NoRootSOA,
              resolver.NXDOMAIN,
              socket.error,
            ) as e:
              outf_lines.append(
                'DNS or socket error when querying %s: %s' % (
                  srv_prefix,
                  form.utf2display(unicode(e)),
                )
              )
            else:
              if dns_result:
                ldap_srv_results.append((url_scheme,dns_result))

        if ldap_srv_results:

          outf_lines.append('<h2>Found SRV RRs</h2>\n')

          # Display SRV search results
          for url_scheme,srv_result in ldap_srv_results:
            for priority, weight, port, hostname in srv_result:
              outf_lines.append('<p>Found SRV record: %s:%d (priority %d, weight %d)</p>' % (
                  hostname,port,priority,weight,
                )
              )
              try:
                host_address = socket.gethostbyname(hostname)
              except socket.error as e:
                outf_lines.append('<p class="ErrorMessage">Did not find IP address for hostname <em>%s</em>.</p>' % (
                  form.utf2display(hostname.decode('ascii'))
                ))
              else:
                ldap_url = ExtendedLDAPUrl(
                  urlscheme=url_scheme,
                  hostport='%s:%d' % (hostname,port),
                  dn=search_base,
                  scope=ldap0.SCOPE_BASE,
                  extensions=lu_extensions
                )
                outf_lines.append("""
                  <p>IP address found for host name %s: %s</p>
                  <table>
                    <tr>
                      <td>%s</td>
                      <td><a href="%s">%s</a></td>
                    </tr>
                """ % (
                    hostname,
                    host_address,
                    web2ldap.app.gui.LDAPURLButton(None,form,None,str(ldap_url)),
                    ldap_url.unparse(),
                    ldap_url.unparse(),
                  )
                )

              if locate_name_type==LOCATE_NAME_RFC822:
                ldap_url = ExtendedLDAPUrl(
                  urlscheme=url_scheme,
                  hostport='%s:%d' % (hostname,port),
                  dn=search_base,
                  scope=ldap0.SCOPE_SUBTREE,
                  filterstr='(mail=%s)' % (locate_name),
                  extensions=lu_extensions
                )
                outf_lines.append("""<tr>
              <td>%s</td>
              <td><a href="%s">Search %s</a></td>
            </tr>
        """ % (
                    web2ldap.app.gui.LDAPURLButton(None,form,None,ldap_url),
                    ldap_url.unparse(),
                    ldap_url.unparse(),
                  )
                )
              outf_lines.append('</table>\n')

        host_addresses = []
        # Search for well known aliases of LDAP servers under dns_name
        for alias in ldap_hostname_aliases:
          alias_name = '.'.join([alias,dns_name])
          try:
            host_address = socket.gethostbyname(alias_name)
          except socket.error:
            pass
          else:
            host_addresses.append(host_address)

        if host_addresses:
          outf_lines.append('<h2>Found well known aliases</h2>\n')
          for host_address in host_addresses:
            ldap_url = ExtendedLDAPUrl(
              hostport=alias_name,
              dn=search_base,
              scope=ldap0.SCOPE_BASE
            )
            outf_lines.append("""
      <p>IP address found for host name %s: %s</p>
      <table>
        <tr>
          <td>%s</td>
          <td><a href="%s">%s</a></td>
        </tr>
      </table>
    """ % (
                alias_name,
                host_address,
                web2ldap.app.gui.LDAPURLButton(None,form,None,ldap_url),
                ldap_url.unparse(),
                ldap_url.unparse(),
              )
            )

  web2ldap.app.gui.TopSection(None,outf,command,form,None,None,'DNS lookup',web2ldap.app.gui.EntryMainMenu(form,env),[])

  outf.write("""
  <h1>Locate LDAP host via DNS</h1>
  %s
  %s
  <form
    action="%s/locate"
    method="GET"
    enctype="application/x-www-form-urlencoded"
    accept-charset="%s"
  >
    <fieldset title="Locate LDAP host by DNS name or DN.">
      <input type="submit" value="Locate"><br>
      <p>
        Search for well-known DNS aliases of LDAP servers and DNS SRV 
        records in a given DNS domain by entering e-mail address, DNS 
        domain or dc-style DN:
      </p>
      <p>
        <input name="locate_name" size="60">
      </p>
    </fieldset>
  </form>
""" % (
    msg_html,
    '\n'.join(outf_lines),
    form.script_name,
    form.accept_charset,
  )
)

  web2ldap.app.gui.Footer(outf,form)
