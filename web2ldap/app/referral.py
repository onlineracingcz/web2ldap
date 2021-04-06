# -*- coding: utf-8 -*-
"""
web2ldap.app.referral: chase LDAP referrals

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import time

from ldap0.ldapurl import LDAPUrl

from .gui import (
    footer,
    main_menu,
    read_template,
    search_root_field,
    top_section,
)

ERR_MSG_DIV = """
<h1>Error</h1>
<p class="ErrorMessage">
  %s
</p>
"""

def w2l_chasereferral(app, ref_exc):
    """
    Present an input form to change to a server referenced by referral
    """

    top_section(app, 'Referral received', main_menu(app), context_menu_list=[])

    # Pull out referral LDAP URL
    try:
        ldap_url_info = [
            s.strip()
            for s in ref_exc.args[0].get('info', b'').decode(app.ls.charset).split('\n')
        ]
    except ValueError:
        app.outf.write(
            ERR_MSG_DIV % (
                'Error extracting referral LDAP URL from %s.' % (
                    app.form.utf2display(str(repr(ref_exc), 'ascii'))
                )
            )
        )
        footer(app)
        return

    try:
        ldap_url_info = ldap_url_info[1]
    except IndexError:
        app.outf.write(
            ERR_MSG_DIV % (
                'Error extracting referral LDAP URL from %s.' % (
                    app.form.utf2display(repr(ldap_url_info).decode('ascii'))
                )
            )
        )
        footer(app)
        return

    # Parse the referral LDAP URL
    try:
        ref_url = LDAPUrl(ldap_url_info[ldap_url_info.find('ldap:'):])
    except ValueError as value_error:
        app.outf.write(
            ERR_MSG_DIV % (
                'Error parsing referral URL %s: %s' % (
                    app.form.utf2display(repr(ldap_url_info).decode('ascii')),
                    app.form.utf2display(str(value_error).decode('ascii'))
                )
            )
        )
        footer(app)
        return

    login_template_str = read_template(
        app, 'login_template', u'referral login form'
    )

    login_search_root_field = search_root_field(
        app,
        name='login_search_root',
    )
    login_fields = login_template_str.format(
        field_login_mech=app.form.field['login_mech'].input_html(),
        value_ldap_who=app.form.utf2display(app.ls.who),
        value_ldap_mapping=app.form.utf2display(app.binddn_mapping),
        field_login_search_root=login_search_root_field.input_html(),
        field_login_authzid_prefix=app.form.field['login_authzid_prefix'].input_html(),
        value_submit='Chase Referral',
        value_currenttime=time.strftime(r'%Y%m%d%H%M%SZ', time.gmtime()),
    )

    app.outf.write(
        """
        <h1>Referral received</h1>
        <p>
          Referral URL:<br>%s
        </p>
        %s\n%s\n%s\n%s
        """  % (
            app.form.utf2display(ref_url.unparse()),
            app.begin_form(app.command, 'POST'),
            app.form.hiddenFieldHTML('host', ref_url.hostport, u''),
            app.form.hiddenFieldHTML('dn', ref_url.dn, u''),
            login_fields,
        )
    )
    app.form.hidden_fields(
        app.outf,
        ignore_fields={'sid', 'host', 'dn', 'who', 'cred', 'login_search_root'},
    )
    app.outf.write('</form>\n')

    footer(app)
