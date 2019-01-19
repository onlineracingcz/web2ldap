# -*- coding: utf-8 -*-
"""
web2ldap.app.login: bind with a specific bind DN and password

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time

import web2ldap.app.core
import web2ldap.app.gui
import web2ldap.app.cnf
from web2ldap.log import logger


def w2l_login(
        app,
        title_msg=u'Bind',
        login_msg='',
        who=u'',
        relogin=False,
        nomenu=False,
        login_default_mech=None
    ):
    """
    Provide a input form for doing a (re-)login
    """

    login_search_root = (
        app.form.getInputValue('login_search_root', [u''])[0] or
        app.naming_context or
        app.dn
    )

    if 'login_who' in app.form.inputFieldNames:
        who = app.form.field['login_who'].value[0]

    login_search_root = login_search_root or app.dn

    login_search_root_field = web2ldap.app.gui.SearchRootField(
        app,
        name='login_search_root',
    )
    login_search_root_field.setDefault(login_search_root)

    login_template_str = web2ldap.app.gui.ReadTemplate(app, 'login_template', u'login form')

    if nomenu:
        main_menu_list = []
    else:
        main_menu_list = web2ldap.app.gui.MainMenu(app)

    web2ldap.app.gui.TopSection(
        app,
        login_msg,
        main_menu_list,
        context_menu_list=[],
        main_div_id='Input',
    )

    if app.ls.rootDSE:
        app.form.field['login_mech'].setOptions(app.ls.supportedSASLMechanisms or [])

    # Determine the bind mech to be used from the
    # form data or the key-word argument login_default_mech
    login_mech = app.form.getInputValue('login_mech', [login_default_mech] or u'')[0]

    login_fields = login_template_str.format(
        field_login_mech=app.form.field['login_mech'].inputHTML(default=login_mech),
        value_ldap_who=app.form.utf2display(who),
        value_ldap_filter=app.form.utf2display(app.binddnsearch),
        field_login_search_root=login_search_root_field.inputHTML(),
        field_login_authzid_prefix=app.form.field['login_authzid_prefix'].inputHTML(),
        value_submit={False:'Login', True:'Retry w/login'}[relogin],
        value_currenttime=time.strftime(r'%Y%m%d%H%M%SZ', time.gmtime()),
    )

    scope_str = app.form.getInputValue('scope', [None])[0]
    if not scope_str and app.ldap_url.scope is not None:
        scope_str = unicode(app.ldap_url.scope)
    if scope_str:
        scope_hidden_field = app.form.hiddenFieldHTML('scope', scope_str, u'')
    else:
        scope_hidden_field = ''

    filterstr = app.form.getInputValue(
        'filterstr',
        [(app.ldap_url.filterstr or '').decode(app.ls.charset)],
    )[0]
    if filterstr:
        filterstr_hidden_field = app.form.hiddenFieldHTML('filterstr', filterstr, u'')
    else:
        filterstr_hidden_field = ''

    search_attrs_hidden_field = ''
    if app.command in {'search', 'searchform'}:
        search_attrs = app.form.getInputValue('search_attrs', [u','.join(app.ldap_url.attrs or [])])[0]
        if search_attrs:
            search_attrs_hidden_field = app.form.hiddenFieldHTML('search_attrs', search_attrs, u'')

    if login_msg:
        login_msg_html = '<p class="ErrorMessage">%s</p>' % (login_msg)
    else:
        login_msg_html = ''

    app.outf.write(
        '<h1>%s</h1>\n%s' % (
            app.form.utf2display(title_msg),
            '\n'.join((
                login_msg_html,
                app.form.beginFormHTML(app.command, None, 'POST', None),
                app.form.hiddenFieldHTML('ldapurl', str(app.ls.ldapUrl('')).decode('ascii'), u''),
                app.form.hiddenFieldHTML('dn', app.dn, u''),
                app.form.hiddenFieldHTML('delsid', app.sid.decode('ascii'), u''),
                app.form.hiddenFieldHTML('conntype', unicode(int(app.ls.startTLSOption > 0)), u''),
                scope_hidden_field,
                filterstr_hidden_field,
                login_fields,
                search_attrs_hidden_field,
            ))
        )
    )
    if relogin:
        app.outf.write(
            app.form.hiddenInputHTML(
                ignoreFieldNames=set([
                    'sid', 'delsid',
                    'ldapurl', 'conntype', 'host', 'who', 'cred',
                    'dn', 'scope', 'filterstr', 'search_attrs',
                    'login_mech', 'login_authzid', 'login_authzid_prefix', 'login_realm',
                    'login_search_root', 'login_filterstr'
                ])
            )
        )
    app.outf.write('</form>\n')
    web2ldap.app.gui.Footer(app)
