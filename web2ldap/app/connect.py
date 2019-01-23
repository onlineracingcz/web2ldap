# -*- coding: utf-8 -*-
"""
web2ldap.app.connect: present connect dialogue for choosing server

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time

import web2ldap.web.forms

# Modules shipped with web2ldap
import web2ldapcnf
import web2ldapcnf.hosts

import web2ldap.app.core
import web2ldap.app.gui

##############################################################################
# Connect form
##############################################################################

def w2l_connect(app, h1_msg='Connect', error_msg=''):
    """
    Display the landing page with a connect form
    """

    connect_template_str = web2ldap.app.gui.read_template(
        app, None, u'connect form',
        tmpl_filename=web2ldapcnf.connect_template
    )

    if web2ldapcnf.hosts.ldap_uri_list:
        uri_select_field = web2ldap.web.forms.Select(
            'ldapurl',
            u'LDAP uri',
            1,
            options=web2ldapcnf.hosts.ldap_uri_list,
        )
        uri_select_field.charset = 'utf-8'
        uri_select_field_html = uri_select_field.inputHTML(
            title=u'List of pre-configured directories to connect to',
        )
    else:
        uri_select_field_html = ''

    if error_msg:
        error_msg = '<p class="ErrorMessage">%s</p>' % (error_msg)

    app.simple_message(
        'Connect',
        connect_template_str.format(
            text_scriptname=app.env.get('SCRIPT_NAME', '').decode('utf-8'),
            text_heading=h1_msg,
            text_error=error_msg,
            form_begin=app.begin_form('searchform', 'GET'),
            field_uri_select=uri_select_field_html,
            disable_start={False:'', True:'<!--'}[web2ldapcnf.hosts.restricted_ldap_uri_list],
            disable_end={False:'', True:'-->'}[web2ldapcnf.hosts.restricted_ldap_uri_list],
            value_currenttime=time.strftime(r'%Y%m%d%H%M%SZ', time.gmtime()),
        ),
        main_menu_list=web2ldap.app.gui.simple_main_menu(app),
        context_menu_list=[],
    )
