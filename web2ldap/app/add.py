# -*- coding: utf-8 -*-
"""
web2ldap.app.add: add an entry

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0
import ldap0.modlist
from ldap0.controls.readentry import PostReadControl
from ldap0.dn import DNObj

import web2ldap.web.forms
from web2ldap.web import escape_html
import web2ldap.app.cnf
import web2ldap.app.core
import web2ldap.app.gui
import web2ldap.app.schema
import web2ldap.app.addmodifyform

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


def ModlistTable(schema, modlist):
    """
    Return a string containing a HTML table showing attr type/value pairs
    """
    s = []
    s.append('<table summary="Modify list">')
    for attr_type, attr_value in modlist:
        if web2ldap.app.schema.no_humanreadable_attr(schema, attr_type):
            tablestr = '%s bytes of binary data' % (
                ' + '.join([str(len(x)) for x in attr_value])
            )
        else:
            tablestr = '<br>'.join([
                escape_html(repr(v))
                for v in attr_value
            ])
        s.append('<tr><td>%s</td><td>%s</td></tr>' % (
            escape_html(attr_type),
            tablestr,
        ))
    s.append('</table>')
    return '\n'.join(s) # ModlistTable()


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
        entry, _ = web2ldap.app.addmodifyform.read_old_entry(app, add_clonedn, app.schema, None, {'*':'*'})
        add_clonedn_obj = DNObj.fromstring(add_clonedn)
        add_rdn = u'+'.join(['%s=' % (at) for at, _ in add_clonedn_obj[0]])
        add_basedn = str(add_clonedn_obj.parent()) or app.dn
    elif add_template:
        add_dn, entry = web2ldap.app.addmodifyform.ReadLDIFTemplate(app, add_template)
        add_dn_obj = DNObj.fromstring(add_dn.decode(app.ls.charset))
        add_rdn, add_basedn = str(add_dn_obj.rdn()), str(add_dn_obj.parent())
        add_basedn = add_basedn or app.dn
        entry = ldap0.schema.models.Entry(app.schema, add_basedn.encode(app.ls.charset), entry)
    else:
        entry, invalid_attrs = web2ldap.app.addmodifyform.get_entry_input(app)
        add_rdn = app.form.getInputValue('add_rdn', [''])[0]
        add_basedn = app.form.getInputValue('add_basedn', [app.dn])[0]

    if invalid_attrs:
        invalid_attr_types_ui = [
            app.form.utf2display(at)
            for at in sorted(invalid_attrs.keys())
        ]
        error_msg = 'Wrong syntax in following attributes: %s' % (
            ', '.join([
                '<a class="CL" href="#in_a_%s">%s</a>' % (v, v)
                for v in invalid_attr_types_ui
            ])
        )
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
        web2ldap.app.addmodifyform.w2l_addform(
            app,
            add_rdn, add_basedn, entry,
            msg=error_msg,
            invalid_attrs=invalid_attrs,
        )
        return

    # Filter out empty values
    for attr_type, attr_values in entry.items():
        entry[attr_type] = filter(None, attr_values)

    # If rdn does not contain a complete RDN try to determine
    # the attribute type for forming the RDN.
    try:
        rdn_list = [
            tuple(rdn_comp.split('=', 1))
            for rdn_comp in DNObj.fromstring(add_rdn)
        ]
    except ldap0.DECODING_ERROR:
        web2ldap.app.addmodifyform.w2l_addform(
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
            rdn_list[i] = rdn_attr_type, entry[rdn_attr_type][0]
        else:
            web2ldap.app.addmodifyform.w2l_addform(
                app,
                add_rdn.decode(app.ls.charset),
                add_basedn, entry,
                msg='Attribute <var>%s</var> required for RDN not in entry data.' % (
                    app.form.utf2display(rdn_attr_type.decode('ascii'))
                ),
            )
            return

    # Join the list of RDN components to one RDN string
    rdn = DNObj((tuple(rdn_list),))

    # Generate list of modifications
    modlist = ldap0.modlist.add_modlist(
        dict(entry.items()),
        ignore_attr_types=ADD_IGNORE_ATTR_TYPES,
    )

    if not modlist:
        raise web2ldap.app.core.ErrorExit(u'Cannot add entry without attribute values.')

    if app.dn:
        new_dn = rdn + DNObj.fromstring(add_basedn)
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
            new_dn.encode(app.ls.charset),
            modlist,
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
        ) as e:
        # Some error in user's input => present input form to edit input values
        web2ldap.app.addmodifyform.w2l_addform(
            app,
            add_rdn.decode(app.ls.charset), add_basedn.decode(app.ls.charset), entry,
            msg=app.ldap_error_msg(e),
        )
    else:
        # Try to extract Post Read Entry response control
        prec_ctrls = [
            c
            for c in add_result.ctrls or []
            if c.controlType == PostReadControl.controlType
        ]
        if prec_ctrls:
            new_dn = prec_ctrls[0].dn
        new_dn_u = new_dn.decode(app.ls.charset)
        app.simple_message(
            'Added Entry',
            """
            <p class="SuccessMessage">Successfully added new entry.</p>
            <p>%s</p>
            <dl>
              <dt>Distinguished name:</dt>
              <dd>%s</dd>
              <dt>Entry data:</dt>
              <dd>%s</dd>
            </dl>
            """ % (
                app.anchor(
                    'read', 'Read added entry',
                    [('dn', new_dn_u)],
                    title=u'Display added entry %s' % new_dn_u,
                ),
                app.display_dn(new_dn_u, commandbutton=0),
                ModlistTable(app.schema, modlist)
            ),
            main_menu_list=web2ldap.app.gui.main_menu(app),
            context_menu_list=[]
        )
