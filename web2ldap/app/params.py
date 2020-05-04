# -*- coding: utf-8 -*-
"""
web2ldap.app.params: Display (SSL) connection data

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2020 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import web2ldap.ldapsession
import web2ldap.app.cnf
import web2ldap.app.core
import web2ldap.app.gui
from web2ldap.ldaputil.oidreg import OID_REG
from web2ldap.ldapsession import AVAILABLE_BOOLEAN_CONTROLS


##############################################################################
# LDAP connection parameters
##############################################################################

def w2l_params(app):

    # Set the LDAP connection option for deferencing aliases
    ldap_deref = app.form.getInputValue('ldap_deref', [])
    if ldap_deref:
        app.ls.l.deref = int(ldap_deref[0])

    web2ldap.app.gui.top_section(
        app,
        'LDAP Connection Parameters',
        web2ldap.app.gui.main_menu(app),
        context_menu_list=[]
    )

    ldapparam_all_controls = app.form.getInputValue('params_all_controls', [u'0'])[0] == u'1'

    ldapparam_enable_control = app.form.getInputValue('params_enable_control', [None])[0]
    if ldapparam_enable_control and ldapparam_enable_control in AVAILABLE_BOOLEAN_CONTROLS:
        methods, control_class, control_value = AVAILABLE_BOOLEAN_CONTROLS[ldapparam_enable_control]
        for method in methods:
            if control_value is not None:
                app.ls.l.add_server_control(
                    method,
                    control_class(ldapparam_enable_control, 1, control_value)
                )
            else:
                app.ls.l.add_server_control(
                    method,
                    control_class(ldapparam_enable_control, 1)
                )

    ldapparam_disable_control = app.form.getInputValue('params_disable_control', [None])[0]
    if ldapparam_disable_control and \
       ldapparam_disable_control in AVAILABLE_BOOLEAN_CONTROLS:
        methods, control_class, control_value = \
            AVAILABLE_BOOLEAN_CONTROLS[ldapparam_disable_control]
        for method in methods:
            app.ls.l.del_server_control(method, ldapparam_disable_control)

    # Determine which controls are enabled
    enabled_controls = set()
    for control_oid, control_spec in AVAILABLE_BOOLEAN_CONTROLS.items():
        methods, control_class, control_value = control_spec
        control_enabled = True
        for method in methods:
            control_enabled = control_enabled and (control_oid in app.ls.l.get_ctrls(method))
        if control_enabled:
            enabled_controls.add(control_oid)

    # Prepare input fields for LDAPv3 controls
    control_table_rows = []
    for control_oid in AVAILABLE_BOOLEAN_CONTROLS:
        control_enabled = (control_oid in enabled_controls)
        if not (control_enabled or ldapparam_all_controls or control_oid in app.ls.supportedControl):
            continue
        name, description, _ = OID_REG[control_oid]
        control_table_rows.append(
            """
            <tr>
              <td>%s</td>
              <td>%s%s%s</td>
              <td>%s</td>
              <td>%s</td>
            </tr>
            """ % (
                app.anchor(
                    'params',
                    {False:'Enable', True:'Disable'}[control_enabled],
                    [
                        ('dn', app.dn),
                        (
                            'params_%s_control' % {
                                False:'enable',
                                True:'disable',
                            }[control_enabled],
                            control_oid
                        ),
                    ],
                    title=u'%s %s' % (
                        {False:u'Enable', True:u'Disable'}[control_enabled],
                        name,
                    ),
                ),
                {False:'<strike>', True:''}[control_oid in app.ls.supportedControl],
                app.form.utf2display(name),
                {False:'</strike>', True:''}[control_oid in app.ls.supportedControl],
                app.form.utf2display(control_oid),
                app.form.utf2display(description),
            )
        )

    app.outf.write(
        """
        <h1>LDAP Options</h1>
        <p>Jump to another entry by entering its DN:</p>
        %s
        <p>Alias dereferencing:</p>
        %s
        <h2>LDAPv3 extended controls</h2>
        <p>List %s controls</p>
        <table id="booleancontrolstable" summary="Simple boolean controls">
          <tr>
            <th>&nbsp;</th>
            <th>Name</th>
            <th>OID</th>
            <th>Description</th>
          </tr>
          %s
            </table>
          </fieldset>
        """ % (
            app.form_html(
                'read', 'Go to', 'GET', [],
                extrastr=app.form.field['dn'].input_html(),
            ),
            app.form_html(
                'params', 'Set alias deref', 'GET', [],
                extrastr=app.form.field['ldap_deref'].input_html(default=str(app.ls.l.deref)),
            ),
            app.anchor(
                'params',
                {False:'all', True:'only known'}[ldapparam_all_controls],
                [
                    ('dn', app.dn),
                    ('params_all_controls', str(int(not ldapparam_all_controls))),
                ],
                title=u'Show %s controls' % (
                    {False:u'all', True:u'known'}[ldapparam_all_controls],
                ),
            ),
            '\n'.join(control_table_rows),
        )
    )

    web2ldap.app.gui.footer(app)
