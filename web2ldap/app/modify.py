# -*- coding: utf-8 -*-
"""
web2ldap.app.modify: modify an entry

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

from cStringIO import StringIO

import ldap0
import ldap0.ldif
import ldap0.schema
from ldap0.schema.models import AttributeType
from ldap0.modlist import modify_modlist2

import web2ldap.ldapsession
import web2ldap.app.core
import web2ldap.app.cnf
import web2ldap.app.gui
import web2ldap.app.addmodifyform
import web2ldap.app.add
import web2ldap.app.schema
from web2ldap.app.schema.syntaxes import syntax_registry, LDAPSyntaxValueError


def get_entry_input(app, sub_schema):

    # Get all the attribute types
    in_attrtype_list = [
        a.encode('ascii')
        for a in app.form.getInputValue('in_at', [])
    ]
    # Grab the raw input strings
    in_value_indexes = [
        a for a in app.form.getInputValue('in_avi', [])
    ]
    # Grab the raw input strings
    in_value_list = [
        a for a in app.form.getInputValue('in_av', [])
    ]

    if not len(in_attrtype_list) == len(in_value_list) == len(in_value_indexes):
        raise web2ldap.app.core.ErrorExit(u'Different count of attribute types and values input.')

    entry = ldap0.schema.models.Entry(sub_schema, app.ldap_dn, {})

    # Stuff input field lists into raw dictionary
    for i, attr_type in enumerate(in_attrtype_list):
        attr_value = in_value_list[i]
        if isinstance(attr_value, unicode):
            attr_value = attr_value.encode(app.ls.charset)
        try:
            entry[attr_type].append(attr_value)
        except KeyError:
            entry[attr_type] = [attr_value]

    # Convert input field string representation into potential LDAP string representation
    # sanitize 'objectClass' first
    attr_type = 'objectClass'
    attr_values = []
    for in_value in entry.get(attr_type, []):
        attr_instance = syntax_registry.get_at(
            app, app.dn, sub_schema,
            attr_type, None,
            entry=entry,
        )
        try:
            attr_value = attr_instance.sanitizeInput(in_value)
        except LDAPSyntaxValueError:
            attr_value = in_value
        attr_values.append(attr_value)
    entry[attr_type] = attr_values

    # sanitize rest of dict
    for attr_type, in_values in entry.items():
        if attr_type == '2.5.4.0':
            # ignore object class attribute herein
            continue
        attr_values = []
        for in_value in in_values:
            attr_instance = syntax_registry.get_at(
                app, app.dn, sub_schema,
                attr_type, None,
                entry=entry,
            )
            try:
                attr_value = attr_instance.sanitizeInput(in_value)
            except LDAPSyntaxValueError:
                attr_value = in_value
            attr_values.append(attr_value)
        entry[attr_type] = attr_values

    # extend entry with LDIF input
    try:
        in_ldif = app.form.field['in_ldif'].getLDIFRecords()
    except ValueError as e:
        raise web2ldap.app.core.ErrorExit(
            u'LDIF parsing error: %s' % (app.form.utf2display(unicode(e)))
        )
    else:
        if in_ldif:
            entry.update(in_ldif[0][1])

    # Transmuting whole attribute value lists into final LDAP string
    # representation which may be an interative result
    iteration_count = 7
    entry_changed = True
    while entry_changed and iteration_count:
        iteration_count -= 1
        entry_changed = False
        for attr_type, attr_values in entry.items():
            attr_instance = syntax_registry.get_at(
                app, app.dn, sub_schema,
                attr_type, None,
                entry=entry,
            )
            try:
                new_values = attr_instance.transmute(attr_values)
            except (KeyError, IndexError):
                entry_changed = True
                entry[attr_type] = ['']
            else:
                entry_changed = entry_changed or (new_values != attr_values)
                entry[attr_type] = new_values

    invalid_attrs = {}

    # Checking for invalid input done after sanitizing all values so
    # plugin classes can use all entry's attributes for cross-checking input
    for attr_type, attr_values in entry.items():
        attr_values = entry[attr_type]
        if not attr_values:
            del entry[attr_type]
            continue
        attr_instance = syntax_registry.get_at(
            app, app.dn, sub_schema,
            attr_type, None,
            entry=entry,
        )
        for attr_index, attr_value in enumerate(attr_values):
            if attr_value:
                try:
                    attr_instance.validate(attr_value)
                except LDAPSyntaxValueError:
                    try:
                        invalid_attrs[unicode(attr_type)].append(attr_index)
                    except KeyError:
                        invalid_attrs[unicode(attr_type)] = [attr_index]

    return entry, invalid_attrs # get_entry_input()


def modlist_ldif(dn, form, modlist):
    """
    Return a string containing a HTML-formatted LDIF change record
    """
    s = []
    s.append('<pre>')
    f = StringIO()
    ldif_writer = ldap0.ldif.LDIFWriter(f)
    ldif_writer.unparse(dn.encode('utf-8'), modlist)
    s.append(form.utf2display(f.getvalue().decode('utf-8')).replace('\n', '<br>'))
    s.append('</pre>')
    return ''.join(s) # modlist_ldif()


##############################################################################
# Modify existing entry
##############################################################################

def w2l_modify(app):

    sub_schema = app.ls.retrieveSubSchema(
        app.dn,
        web2ldap.app.cnf.GetParam(app.ls, '_schema', None),
        web2ldap.app.cnf.GetParam(app.ls, 'supplement_schema', None),
        web2ldap.app.cnf.GetParam(app.ls, 'schema_strictcheck', True),
    )

    in_assertion = app.form.getInputValue('in_assertion', [u'(objectClass=*)'])[0]

    input_modrow = app.form.getInputValue('in_mr', ['.'])[0]

    if input_modrow[0] == '-':
        del_row_num = int(input_modrow[1:])
        in_at_len = len(app.form.field['in_at'].value)
        if in_at_len >= del_row_num+2 and \
           app.form.field['in_at'].value[del_row_num] == app.form.field['in_at'].value[del_row_num+1] or \
           in_at_len >= 1 and \
           app.form.field['in_at'].value[del_row_num] == app.form.field['in_at'].value[del_row_num-1]:
            # more input fields for same attribute type => pop()
            app.form.field['in_at'].value.pop(del_row_num)
            app.form.field['in_av'].value.pop(del_row_num)
        else:
            # only delete attribute value
            app.form.field['in_av'].value[del_row_num] = ''
        app.form.field['in_avi'].value = map(str, range(0, len(app.form.field['in_av'].value)))
    elif input_modrow[0] == '+':
        insert_row_num = int(input_modrow[1:])
        app.form.field['in_at'].value.insert(insert_row_num+1, app.form.field['in_at'].value[insert_row_num])
        app.form.field['in_av'].value.insert(insert_row_num+1, '')
        app.form.field['in_avi'].value = map(str, range(0, len(app.form.field['in_av'].value)))

    new_entry, invalid_attrs = get_entry_input(app, sub_schema)

    if invalid_attrs:
        invalid_attr_types_ui = [
            app.form.utf2display(at)
            for at in sorted(invalid_attrs.keys())
        ]
        error_msg = 'Wrong syntax in following attributes: %s' % (
            ', '.join([
                '<a class="CommandLink" href="#in_a_%s">%s</a>' % (v, v)
                for v in invalid_attr_types_ui
            ])
        )
    else:
        error_msg = ''

    # Check if the user just switched/modified input form
    if 'in_ft' in app.form.inputFieldNames or \
       'in_oc' in app.form.inputFieldNames or \
       'in_mr' in app.form.inputFieldNames or \
       not new_entry or \
       invalid_attrs:
        web2ldap.app.addmodifyform.w2l_modifyform(
            app,
            new_entry,
            Msg=error_msg,
            invalid_attrs=invalid_attrs,
        )
        return

    in_oldattrtypes = {}
    for a in app.form.getInputValue('in_oldattrtypes', []):
        attr_type = a.encode('ascii')
        in_oldattrtypes[attr_type] = None

    try:
        old_entry, dummy = web2ldap.app.addmodifyform.ReadOldEntry(app.ls, app.dn, sub_schema, in_assertion)
    except ldap0.NO_SUCH_OBJECT:
        raise web2ldap.app.core.ErrorExit(u'Old entry was removed or modified in between! You have to edit it again.')

    # Filter out empty values
    for attr_type, attr_values in new_entry.items():
        new_entry[attr_type] = filter(None, attr_values)

    # Set up a dictionary of all attribute types to be ignored
    ignore_attr_types = ldap0.schema.models.SchemaElementOIDSet(
        sub_schema,
        AttributeType,
        web2ldap.app.add.ADD_IGNORE_ATTR_TYPES,
    )

    # Determine whether Relax Rules control is in effect
    relax_rules_enabled = app.ls.l._get_server_ctrls('**write**').has_key(web2ldap.ldapsession.CONTROL_RELAXRULES)

    if not relax_rules_enabled:
        # Add all attributes which have NO-USER-MODIFICATION set
        ignore_attr_types.update(sub_schema.no_user_mod_attr_oids)
        # Ignore attributes which are assumed to be constant (some operational attributes)
        ignore_attr_types.update(web2ldap.app.addmodifyform.ConfiguredConstantAttributes(app.ls).values())

    # All attributes currently read which were not visible before
    # must be ignored to avoid problems with different access rights
    # after possible re-login
    ignore_attr_types.update([
        a
        for a in old_entry.keys()
        if not in_oldattrtypes.has_key(a)
    ])

    old_entry_structural_oc = old_entry.get_structural_oc()
    # Ignore binary attributes from old entry data in any case
    for attr_type in old_entry.keys():
        syntax_class = syntax_registry.get_syntax(sub_schema, attr_type, old_entry_structural_oc)
        if not syntax_class.editable:
            ignore_attr_types.add(attr_type)

    try:
        ignore_attr_types.remove('2.5.4.0')
    except KeyError:
        pass

    # Create modlist containing deltas
    modlist = modify_modlist2(
        sub_schema,
        old_entry, new_entry,
        ignore_attr_types=ignore_attr_types,
        ignore_oldexistent=False,
    )
    # Binary values are always replaced
    new_entry_structural_oc = new_entry.get_structural_oc()
    for attr_type in new_entry.keys():
        syntax_class = syntax_registry.get_syntax(sub_schema, attr_type, new_entry_structural_oc)
        if (not syntax_class.editable) and \
           new_entry[attr_type] and \
           (not attr_type in old_entry or new_entry[attr_type] != old_entry[attr_type]):
            modlist.append((ldap0.MOD_REPLACE, attr_type, new_entry[attr_type]))

    if not modlist:
        # nothing to be changed
        web2ldap.app.gui.SimpleMessage(
            app,
            'Modify result',
            '<p class="SuccessMessage">No attributes modified of entry %s</p>' % (
                web2ldap.app.gui.DisplayDN(app, app.dn, commandbutton=True),
            ),
            main_menu_list=web2ldap.app.gui.MainMenu(app),
            context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(app)
        )
        return


    # Send modify-list to host
    try:
        app.ls.modifyEntry(
            app.dn,
            modlist,
            assertion_filter=in_assertion,
        )
    except ldap0.ASSERTION_FAILED:
        raise web2ldap.app.core.ErrorExit(
            u'Assertion failed'
            u'=> Entry was removed or modified in between!'
            u'You have to edit it again.'
        )
    except (
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
        # go back to input form so the user can correct something
        web2ldap.app.addmodifyform.w2l_modifyform(
            app,
            new_entry,
            Msg=app.ldap_error_msg(e),
        )
        return

    # Display success message
    web2ldap.app.gui.SimpleMessage(
        app,
        'Modify result',
        '<p class="SuccessMessage">Modified entry %s</p><dt>LDIF change record:</dt>\n<dd>%s</dd>' % (
            web2ldap.app.gui.DisplayDN(app, app.dn, commandbutton=True),
            modlist_ldif(app.dn, app.form, modlist),
        ),
        main_menu_list=web2ldap.app.gui.MainMenu(app),
        context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(app)
    )
