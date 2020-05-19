# -*- coding: utf-8 -*-
"""
web2ldap.app.add: add an entry

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2020 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0
import ldap0.modlist
from ldap0.controls.readentry import PostReadControl
from ldap0.dn import DNObj

import web2ldap.web.forms
import web2ldap.app.cnf
import web2ldap.app.core
import web2ldap.app.gui
import web2ldap.app.schema
from .addmodifyform import w2l_addform, get_entry_input, read_old_entry, read_ldif_template

# Attribute types always ignored for add requests
ADD_IGNORE_ATTR_TYPES = {
    'entryDN',
    'entryCSN',
    'governingStructureRule',
    'hasSubordinates',
    'structuralObjectClass',
    'subschemaSubentry',
    'collectiveAttributeSubentries',
}


def w2l_add(app):

    input_modrow = app.form.getInputValue('in_mr', ['.'])[0]

    if input_modrow[0] == '-':
        del_row_num = int(input_modrow[1:])
        del app.form.field['in_at'].value[del_row_num]
        del app.form.field['in_av'].value[del_row_num]
        # FIX ME! This is definitely not sufficient!
        del app.form.field['in_avi'].value[del_row_num]
    elif input_modrow[0] == '+':
        insert_row_num = int(input_modrow[1:])
        app.form.field['in_at'].value.insert(insert_row_num+1, app.form.field['in_at'].value[insert_row_num])
        app.form.field['in_av'].value.insert(insert_row_num+1, '')
        # FIX ME! This is definitely not sufficient!
        app.form.field['in_avi'].value.insert(insert_row_num+1, app.form.field['in_avi'].value[insert_row_num])

    add_clonedn = app.form.getInputValue('add_clonedn', [None])[0]
    add_template = app.form.getInputValue('add_template', [None])[0]
    invalid_attrs = None

    if add_clonedn:
        entry, _ = read_old_entry(app, add_clonedn, app.schema, None, {'*':'*'})
        add_clonedn_obj = DNObj.from_str(add_clonedn)
        add_rdn = u'+'.join(['%s=' % (at) for at, _ in add_clonedn_obj[0]])
        add_basedn = str(add_clonedn_obj.parent()) or app.dn
    elif add_template:
        add_dn, entry = read_ldif_template(app, add_template)
        add_dn_obj = DNObj.from_str(add_dn.decode(app.ls.charset))
        add_rdn, add_basedn = str(add_dn_obj.rdn()), str(add_dn_obj.parent())
        add_basedn = add_basedn or app.dn
        entry = ldap0.schema.models.Entry(app.schema, add_basedn, entry)
    else:
        entry, invalid_attrs = get_entry_input(app)
        add_rdn = app.form.getInputValue('add_rdn', [''])[0]
        add_basedn = app.form.getInputValue('add_basedn', [app.dn])[0]

    if invalid_attrs:
        error_msg = web2ldap.app.gui.invalid_syntax_message(app, invalid_attrs)
    else:
        error_msg = ''

    if (
            add_clonedn or add_template or
            not entry or
            invalid_attrs or
            'in_mr' in app.form.input_field_names or
            'in_oc' in app.form.input_field_names or
            'in_ft' in app.form.input_field_names
        ):
        w2l_addform(
            app,
            add_rdn, add_basedn, entry,
            msg=error_msg,
            invalid_attrs=invalid_attrs,
        )
        return

    # Filter out empty values
    for attr_type, attr_values in entry.items():
        entry[attr_type] = [av for av in attr_values if av]

    # If rdn does not contain a complete RDN try to determine
    # the attribute type for forming the RDN.
    try:
        rdn_list = list(DNObj.from_str(add_rdn).rdn_attrs().items())
    except ldap0.DECODING_ERROR:
        w2l_addform(
            app,
            add_rdn, add_basedn, entry,
            msg='Wrong format of RDN string.',
        )
        return

    # Automagically derive the RDN from the entry
    for i in range(len(rdn_list)):
        rdn_attr_type, rdn_attr_value = rdn_list[i]
        # Normalize old LDAPv2 RDN form
        if rdn_attr_type.lower().startswith('oid.'):
            rdn_attr_type = rdn_attr_type[4:]
        if rdn_attr_type in entry and (
                (not rdn_attr_value and len(entry[rdn_attr_type]) == 1) or
                rdn_attr_value in entry[rdn_attr_type]
            ):
            rdn_list[i] = rdn_attr_type, entry[rdn_attr_type][0].decode(app.ls.charset)
        else:
            w2l_addform(
                app,
                add_rdn,
                add_basedn, entry,
                msg='Attribute <var>%s</var> required for RDN not in entry data.' % (
                    app.form.utf2display(rdn_attr_type)
                ),
            )
            return

    # Join the list of RDN components to one RDN string
    rdn = DNObj((tuple(rdn_list),))

    # Generate list of modifications
    add_entry = {
        av: avs
        for av, avs in entry.items()
        if av not in ADD_IGNORE_ATTR_TYPES
    }

    if not add_entry:
        raise web2ldap.app.core.ErrorExit(u'Cannot add entry without attribute values.')

    if app.dn:
        new_dn = rdn + DNObj.from_str(add_basedn)
    else:
        # Makes it possible to add entries for a namingContext
        new_dn = rdn

    if PostReadControl.controlType in app.ls.supportedControl:
        add_req_ctrls = [PostReadControl(criticality=False, attrList=['entryUUID'])]
    else:
        add_req_ctrls = None

    # Try to add the new entry
    try:
        add_result = app.ls.l.add_s(
            str(new_dn),
            add_entry,
            req_ctrls=add_req_ctrls
        )
    except ldap0.NO_SUCH_OBJECT as e:
        raise web2ldap.app.core.ErrorExit(
            u"""
            %s<br>
            Probably this superiour entry does not exist:<br>%s<br>
            Maybe wrong base DN in LDIF template?<br>
            """ % (
                app.ldap_error_msg(e),
                app.display_dn(add_basedn.decode(app.ls.charset), commandbutton=0),
            )
        )
    except (
            ldap0.ALREADY_EXISTS,
            ldap0.CONSTRAINT_VIOLATION,
            ldap0.INVALID_DN_SYNTAX,
            ldap0.INVALID_SYNTAX,
            ldap0.NAMING_VIOLATION,
            ldap0.OBJECT_CLASS_VIOLATION,
            ldap0.OTHER,
            ldap0.TYPE_OR_VALUE_EXISTS,
            ldap0.UNDEFINED_TYPE,
            ldap0.UNWILLING_TO_PERFORM,
        ) as err:
        # Some error in user's input => present input form to edit input values
        w2l_addform(app, add_rdn, add_basedn, entry, msg=app.ldap_error_msg(err))
    else:
        # Try to extract Post Read Entry response control
        prec_ctrls = [
            c
            for c in add_result.ctrls or []
            if c.controlType == PostReadControl.controlType
        ]
        if prec_ctrls:
            new_dn = prec_ctrls[0].res.dn_s
        app.simple_message(
            'Added Entry',
            """
            <p class="SuccessMessage">Successfully added new entry.</p>
            <p>%s</p>
            <dl>
              <dt>Distinguished name:</dt>
              <dd>%s</dd>
            </dl>
            """ % (
                app.anchor(
                    'read', 'Read added entry',
                    [('dn', str(new_dn))],
                    title=u'Display added entry %s' % (new_dn,),
                ),
                app.display_dn(str(new_dn), commandbutton=0),
            ),
            main_menu_list=web2ldap.app.gui.main_menu(app),
            context_menu_list=[]
        )
