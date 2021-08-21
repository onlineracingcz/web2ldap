# -*- coding: utf-8 -*-
"""
web2ldap.app.login: bind with a specific bind DN and password

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import time

from ..log import logger
from .gui import footer, main_menu, read_template, search_root_field, top_section


def w2l_login(
        app,
        title_msg='Bind',
        login_msg='',
        who='',
        relogin=False,
        nomenu=False,
        login_default_mech=None
    ):
    """
    Provide a input form for doing a (re-)login
    """

    login_search_root = app.form.getInputValue(
        'login_search_root',
        [app.naming_context or app.dn or ''],
    )[0]

    if 'login_who' in app.form.input_field_names:
        who = app.form.field['login_who'].value[0]

    login_search_root_field = search_root_field(
        app,
        name='login_search_root',
        default=str(login_search_root),
    )

    login_template_str = read_template(app, 'login_template', 'login form')

    if nomenu:
        main_menu_list = []
    else:
        main_menu_list = main_menu(app)

    top_section(
        app,
        login_msg,
        main_menu_list,
        context_menu_list=[],
        main_div_id='Input',
    )

    if app.ls.root_dse:
        app.form.field['login_mech'].set_options(app.ls.supportedSASLMechanisms or [])

    # Determine the bind mech to be used from the
    # form data or the key-word argument login_default_mech
    login_mech = app.form.getInputValue('login_mech', [login_default_mech] or '')[0]

    if login_msg:
        login_msg_html = '<p class="ErrorMessage">%s</p>' % (login_msg)
    else:
        login_msg_html = ''

    login_form_html = login_template_str.format(
        text_heading=app.form.s2d(title_msg),
        text_error=login_msg_html,
        field_login_mech=app.form.field['login_mech'].input_html(default=login_mech),
        value_ldap_who=app.form.s2d(who or ''),
        value_ldap_mapping=app.form.s2d(app.binddn_mapping),
        field_login_search_root=login_search_root_field.input_html(),
        field_login_authzid_prefix=app.form.field['login_authzid_prefix'].input_html(),
        value_submit={False:'Login', True:'Retry w/login'}[relogin],
        value_currenttime=time.strftime(r'%Y%m%d%H%M%SZ', time.gmtime()),
    )

    scope_str = app.form.getInputValue('scope', [None])[0]
    if not scope_str and app.ldap_url.scope is not None:
        scope_str = str(app.ldap_url.scope)
    if scope_str:
        scope_hidden_field = app.form.hidden_field_html('scope', scope_str, '')
    else:
        scope_hidden_field = ''

    if 'filterstr' in app.form.field:
        filterstr = app.form.getInputValue(
            'filterstr',
            [app.ldap_url.filterstr or ''],
        )[0]
    else:
        filterstr = app.ldap_url.filterstr or ''
    if filterstr:
        filterstr_hidden_field = app.form.hidden_field_html('filterstr', filterstr, '')
    else:
        filterstr_hidden_field = ''

    search_attrs_hidden_field = ''
    if 'search_attrs' in app.form.field:
        search_attrs = app.form.getInputValue(
            'search_attrs', [','.join(app.ldap_url.attrs or [])]
        )[0]
        if search_attrs:
            search_attrs_hidden_field = app.form.hidden_field_html('search_attrs', search_attrs, '')

    # determine which command will be put in form's action attribute
    if not app.command or app.command == 'login':
        action_command = 'searchform'
    else:
        action_command = app.command

    logger.debug('Display login form for %r with next command %r', app.dn, action_command)

    app.outf.write(
        '\n'.join((
            app.form.begin_form(action_command, None, 'POST', None),
            app.form.hidden_field_html('ldapurl', str(app.ls.ldap_url('')), ''),
            app.form.hidden_field_html('dn', app.dn, ''),
            app.form.hidden_field_html('delsid', app.sid, ''),
            app.form.hidden_field_html('conntype', str(int(app.ls.use_start_tls > 0)), ''),
            scope_hidden_field,
            filterstr_hidden_field,
            login_form_html,
            search_attrs_hidden_field,
        ))
    )
    if relogin:
        app.outf.write(
            app.form.hidden_input_html(
                ignored_fields=set([
                    'sid', 'delsid',
                    'ldapurl', 'conntype', 'host', 'who', 'cred',
                    'dn', 'scope', 'filterstr', 'search_attrs',
                    'login_mech', 'login_authzid', 'login_authzid_prefix', 'login_realm',
                    'login_search_root',
                ])
            )
        )
    app.outf.write('</form>\n')
    footer(app)
