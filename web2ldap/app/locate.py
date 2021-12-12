# -*- coding: ascii -*-
"""
web2ldap.app.locate: Try to locate a LDAP host with various methods.

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import socket

import ldap0
from ldap0.dn import DNObj
from ldap0.ldapurl import LDAPUrlExtension, LDAPUrlExtensions

from ..ldaputil.extldapurl import ExtendedLDAPUrl
from ..log import logger
from . import ErrorExit
from .gui import simple_main_menu, DNS_AVAIL
if DNS_AVAIL:
    from dns.exception import DNSException
    from ..ldaputil.dns import srv_lookup


LDAP_HOSTNAME_ALIASES = (
    'ldap',
    #'ldaps',
    #'dsa',
    #'x500',
    #'ldapdb',
    #'nds',
    #'openldap',
)

LOCATE_NAME_RFC822 = 0
LOCATE_NAME_DCDN = 1
LOCATE_NAME_DOMAIN = 2

LOCATE_INPUT_FORM_TMPL = """
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
"""

LOCATE_HOST_RESULT_TMPL = """
<p>IP address found for host name %s: %s</p>
<table>
  <tr>
    <td>%s</td>
    <td><a href="%s">%s</a></td>
  </tr>
</table>
"""


def w2l_locate(app):
    """
    Try to locate a LDAP server in DNS by several heuristics
    """

    if not DNS_AVAIL:
        logger.warning('Module package dnspython not installed!')
        raise ErrorExit('No DNS support!')

    locate_name = app.form.getInputValue('locate_name', [''])[0].strip()

    msg_html = ''
    outf_lines = []

    if locate_name:

        # Try to determine the format of the input parameter
        if ldap0.dn.is_dn(locate_name):
            # Use dc-style LDAP DN
            msg_html = 'Input is considered LDAP distinguished name.'
            locate_domain = DNObj.from_str(locate_name).domain(only_dc=False).encode('idna').decode('ascii')
            locate_name_type = LOCATE_NAME_DCDN
        elif '@' in locate_name:
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

            dns_list = locate_domain.lower().split('.')

            for dns_index in range(len(dns_list), 0, -1):

                dns_name = '.'.join([
                    label.encode('idna').decode('ascii')
                    for label in dns_list[-dns_index:]
                ])

                search_base = str(DNObj.from_domain(dns_name))
                if dns_name.endswith('de-mail-test.de') or dns_name.endswith('de-mail.de'):
                    search_base = ','.join((search_base, 'cn=de-mail'))
                    lu_extensions = LDAPUrlExtensions({
                        'x-saslmech':LDAPUrlExtension(
                            critical=0,
                            extype='x-saslmech',
                            exvalue='EXTERNAL'
                        )
                    })
                else:
                    lu_extensions = None

                outf_lines.append('<h1><em>%s</em></h1>\n' % (
                    app.form.s2d(dns_name),
                ))

                ldap_srv_results = []
                for url_scheme in ('ldap', 'ldaps'):
                    # Search for a SRV RR of dns_name
                    srv_prefix = '_%s._tcp' % (url_scheme)
                    try:
                        dns_result = srv_lookup(
                            dns_name,
                            srv_prefix=srv_prefix,
                        )
                    except (DNSException, socket.error) as dns_err:
                        outf_lines.append(
                            'DNS or socket error when querying %s: %s' % (
                                srv_prefix,
                                app.form.s2d(str(dns_err)),
                            )
                        )
                    else:
                        if dns_result:
                            ldap_srv_results.append((url_scheme, dns_result))

                if ldap_srv_results:

                    outf_lines.append('<h2>Found SRV RRs</h2>\n')

                    # Display SRV search results
                    for url_scheme, srv_result in ldap_srv_results:

                        for priority, weight, port, hostname in srv_result:
                            outf_lines.append(
                                '<p>Found SRV record: %s:%d (priority %d, weight %d)</p>' % (
                                    hostname, port, priority, weight,
                                )
                            )
                            try:
                                host_address = socket.gethostbyname(hostname)
                            except socket.error:
                                outf_lines.append(
                                    (
                                        '<p class="ErrorMessage">'
                                        'Did not find IP address for hostname <em>%s</em>.'
                                        '</p>'
                                    ) % (
                                        app.form.s2d(hostname.decode('ascii'))
                                    )
                                )
                            else:
                                ldap_url = ExtendedLDAPUrl(
                                    urlscheme=url_scheme,
                                    hostport='%s:%d' % (hostname, port),
                                    dn=search_base,
                                    scope=ldap0.SCOPE_BASE,
                                    extensions=lu_extensions
                                )
                                outf_lines.append(
                                    """
                                    <p>IP address found for host name %s: %s</p>
                                    <table>
                                      <tr>
                                        <td>%s</td>
                                        <td><a href="%s">%s</a></td>
                                      </tr>
                                    """ % (
                                        hostname,
                                        host_address,
                                        app.ldap_url_anchor(ldap_url),
                                        ldap_url.unparse(),
                                        ldap_url.unparse(),
                                    )
                                )

                            if locate_name_type == LOCATE_NAME_RFC822:
                                ldap_url = ExtendedLDAPUrl(
                                    urlscheme=url_scheme,
                                    hostport='%s:%d' % (hostname, port),
                                    dn=search_base,
                                    scope=ldap0.SCOPE_SUBTREE,
                                    filterstr='(mail=%s)' % (locate_name),
                                    extensions=lu_extensions
                                )
                                outf_lines.append(
                                    """<tr>
                                    <td>%s</td>
                                    <td><a href="%s">Search %s</a></td>
                                    </tr>
                                    """ % (
                                        app.ldap_url_anchor(ldap_url),
                                        ldap_url.unparse(),
                                        ldap_url.unparse(),
                                    )
                                )

                        outf_lines.append('</table>\n')

                host_addresses = []
                # Search for well known aliases of LDAP servers under dns_name
                for alias in LDAP_HOSTNAME_ALIASES:
                    alias_name = '.'.join([alias, dns_name])
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
                        outf_lines.append(
                            LOCATE_HOST_RESULT_TMPL % (
                                alias_name,
                                host_address,
                                app.ldap_url_anchor(ldap_url),
                                ldap_url.unparse(),
                                ldap_url.unparse(),
                            )
                        )

    app.simple_message(
        'DNS lookup',
        LOCATE_INPUT_FORM_TMPL % (
            msg_html,
            '\n'.join(outf_lines),
            app.form.script_name,
            app.form.accept_charset,
        ),
        main_menu_list=simple_main_menu(app),
        context_menu_list=[],
    )
