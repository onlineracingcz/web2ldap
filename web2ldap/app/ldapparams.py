# -*- coding: utf-8 -*-
"""
web2ldap.app.ldapparams: Display (SSL) connection data

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

from ldap0.controls.simple import ValueLessRequestControl, BooleanControl

import web2ldap.ldapsession
import web2ldap.app.cnf
import web2ldap.app.core
import web2ldap.app.gui
from web2ldap.ldaputil.oidreg import OID_REG

AVAILABLE_BOOLEAN_CONTROLS = {
    web2ldap.ldapsession.CONTROL_SUBENTRIES: (
        ('search',), BooleanControl, True
    ),
    web2ldap.ldapsession.CONTROL_LDUP_SUBENTRIES: (
        ('search',), ValueLessRequestControl, None
    ),
    web2ldap.ldapsession.CONTROL_MANAGEDSAIT: (
        ('**all**',), ValueLessRequestControl, None
    ),
    web2ldap.ldapsession.CONTROL_RELAXRULES: (
        ('**write**',), ValueLessRequestControl, None
    ),
    web2ldap.ldapsession.CONTROL_DONOTREPLICATE: (
        ('**write**',), ValueLessRequestControl, None
    ),
    web2ldap.ldapsession.CONTROL_DONTUSECOPY: (
        ('**read**',), ValueLessRequestControl, None
    ),
    web2ldap.ldapsession.CONTROL_DONTUSECOPY_OPENLDAP: (
        ('**read**',), ValueLessRequestControl, None
    ),
    # IBM DS
    web2ldap.ldapsession.CONTROL_SERVERADMINISTRATION: (
        ('**write**',), ValueLessRequestControl, None
    ),
    # "real attributes only" control
    '2.16.840.1.113730.3.4.17': (
        ('**read**',), ValueLessRequestControl, None
    ),
    # "virtual attributes only" control
    '2.16.840.1.113730.3.4.19': (
        ('**read**',), ValueLessRequestControl, None
    ),
    # OpenLDAP's privateDB control for slapo-pcache
    '1.3.6.1.4.1.4203.666.11.9.5.1': (
        ('**all**',), ValueLessRequestControl, None
    ),
    # Omit group referential integrity control
    '1.3.18.0.2.10.26': (
        ('delete', 'rename'), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_EXTENDED_DN_OID
    '1.2.840.113556.1.4.529': (
        ('**read**',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_SHOW_DELETED_OID
    '1.2.840.113556.1.4.417': (
        ('**all**',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_SHOW_RECYCLED_OID
    '1.2.840.113556.1.4.2064': (
        ('search',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_DOMAIN_SCOPE_OID
    '1.2.840.113556.1.4.1339': (
        ('search',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID
    '1.2.840.113556.1.4.2065': (
        ('search',), ValueLessRequestControl, None
    ),
    # Effective Rights control
    '1.3.6.1.4.1.42.2.27.9.5.2': (
        ('search',), ValueLessRequestControl, None
    ),
    # Replication Repair Control
    '1.3.6.1.4.1.26027.1.5.2': (
        ('**write**',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_LAZY_COMMIT_OID
    '1.2.840.113556.1.4.619': (
        ('**write**',), ValueLessRequestControl, None
    ),
}


##############################################################################
# LDAP connection parameters
##############################################################################

def w2l_ldapparams(sid, outf, command, form, ls, dn):

    # Set the LDAP connection option for deferencing aliases
    ldap_deref = form.getInputValue('ldap_deref', [])
    if ldap_deref:
        ls.l.deref = int(ldap_deref[0])

    context_menu_list = []

    web2ldap.app.gui.TopSection(
        sid, outf, command, form, ls, dn,
        'LDAP Connection Parameters',
        web2ldap.app.gui.MainMenu(sid, form, ls, dn),
        context_menu_list=context_menu_list
    )

    ldapparam_all_controls = form.getInputValue('ldapparam_all_controls', [u'0'])[0] == u'1'

    ldapparam_enable_control = form.getInputValue('ldapparam_enable_control', [None])[0]
    if ldapparam_enable_control and ldapparam_enable_control in AVAILABLE_BOOLEAN_CONTROLS:
        methods, control_class, control_value = AVAILABLE_BOOLEAN_CONTROLS[ldapparam_enable_control]
        for method in methods:
            if control_value is not None:
                ls.l.add_server_control(
                    method,
                    control_class(ldapparam_enable_control, 1, control_value)
                )
            else:
                ls.l.add_server_control(
                    method,
                    control_class(ldapparam_enable_control, 1)
                )

    ldapparam_disable_control = form.getInputValue('ldapparam_disable_control', [None])[0]
    if ldapparam_disable_control and \
       ldapparam_disable_control in AVAILABLE_BOOLEAN_CONTROLS:
        methods, control_class, control_value = \
            AVAILABLE_BOOLEAN_CONTROLS[ldapparam_disable_control]
        for method in methods:
            ls.l.del_server_control(method, ldapparam_disable_control)

    # Determine which controls are enabled
    enabled_controls = set()
    for control_oid, control_spec in AVAILABLE_BOOLEAN_CONTROLS.items():
        methods, control_class, control_value = control_spec
        control_enabled = True
        for method in methods:
            control_enabled = control_enabled and (control_oid in ls.l._get_server_ctrls(method))
        if control_enabled:
            enabled_controls.add(control_oid)

    # Prepare input fields for LDAPv3 controls
    control_table_rows = []
    for control_oid in AVAILABLE_BOOLEAN_CONTROLS.keys():
        control_enabled = (control_oid in enabled_controls)
        if not (control_enabled or ldapparam_all_controls or control_oid in ls.supportedControl):
            continue
        name, description, _ = OID_REG[control_oid]
        control_oid_u = unicode(control_oid, 'ascii')
        control_table_rows.append(
            """
            <tr>
              <td>%s</td>
              <td>%s%s%s</td>
              <td>%s</td>
              <td>%s</td>
            </tr>
            """ % (
                form.applAnchor(
                    'ldapparams',
                    {False:'Enable', True:'Disable'}[control_enabled],
                    sid,
                    [
                        ('dn', dn),
                        (
                            'ldapparam_%s_control' % {
                                False:'enable',
                                True:'disable',
                            }[control_enabled],
                            control_oid_u
                        ),
                    ],
                    title=u'%s %s' % (
                        {False:u'Enable', True:u'Disable'}[control_enabled],
                        name,
                    ),
                ),
                {False:'<strike>', True:''}[control_oid in ls.supportedControl],
                form.utf2display(name),
                {False:'</strike>', True:''}[control_oid in ls.supportedControl],
                form.utf2display(control_oid_u),
                form.utf2display(description),
            )
        )

    outf.write(
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
            form.formHTML(
                'read', 'Go to', sid, 'GET', [],
                extrastr=form.field['dn'].inputHTML(),
            ),
            form.formHTML(
                'ldapparams', 'Set alias deref', sid, 'GET', [],
                extrastr=form.field['ldap_deref'].inputHTML(default=str(ls.l.deref)),
            ),
            form.applAnchor(
                'ldapparams',
                {False:'all', True:'only known'}[ldapparam_all_controls],
                sid,
                [
                    ('dn', dn),
                    ('ldapparam_all_controls', unicode(int(not ldapparam_all_controls))),
                ],
                title=u'Show %s controls' % (
                    {False:u'all', True:u'known'}[ldapparam_all_controls],
                ),
            ),
            '\n'.join(control_table_rows),
        )
    )

    web2ldap.app.gui.Footer(outf, form)
