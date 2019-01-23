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

from io import BytesIO

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
from web2ldap.app.schema.syntaxes import syntax_registry


def modlist_ldif(dn, form, modlist):
    """
    Return a string containing a HTML-formatted LDIF change record
    """
    s = []
    s.append('<pre>')
    f = BytesIO()
    ldif_writer = ldap0.ldif.LDIFWriter(f)
    ldif_writer.unparse(dn.encode('utf-8'), modlist)
    s.append(form.utf2display(f.getvalue().decode('utf-8')).replace('\n', '<br>'))
    s.append('</pre>')
    return ''.join(s) # modlist_ldif()


##############################################################################
# Modify existing entry
##############################################################################

def w2l_modify(app):

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

    new_entry, invalid_attrs = web2ldap.app.addmodifyform.get_entry_input(app)

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

    # Check if the user just switched/modified input form
    if 'in_ft' in app.form.input_field_names or \
       'in_oc' in app.form.input_field_names or \
       'in_mr' in app.form.input_field_names or \
       not new_entry or \
       invalid_attrs:
        web2ldap.app.addmodifyform.w2l_modifyform(
            app,
            new_entry,
            msg=error_msg,
            invalid_attrs=invalid_attrs,
        )
        return

    in_oldattrtypes = {}
    for a in app.form.getInputValue('in_oldattrtypes', []):
        attr_type = a.encode('ascii')
        in_oldattrtypes[attr_type] = None

    try:
        old_entry, dummy = web2ldap.app.addmodifyform.read_old_entry(app, app.dn, app.schema, in_assertion)
    except ldap0.NO_SUCH_OBJECT:
        raise web2ldap.app.core.ErrorExit(u'Old entry was removed or modified in between! You have to edit it again.')

    # Filter out empty values
    for attr_type, attr_values in new_entry.items():
        new_entry[attr_type] = filter(None, attr_values)

    # Set up a dictionary of all attribute types to be ignored
    ignore_attr_types = ldap0.schema.models.SchemaElementOIDSet(
        app.schema,
        AttributeType,
        web2ldap.app.add.ADD_IGNORE_ATTR_TYPES,
    )

    # Determine whether Relax Rules control is in effect
    relax_rules_enabled = app.ls.l._get_server_ctrls('**write**').has_key(web2ldap.ldapsession.CONTROL_RELAXRULES)

    if not relax_rules_enabled:
        # Add all attributes which have NO-USER-MODIFICATION set
        ignore_attr_types.update(app.schema.no_user_mod_attr_oids)
        # Ignore attributes which are assumed to be constant (some operational attributes)
        ignore_attr_types.update(web2ldap.app.addmodifyform.ConfiguredConstantAttributes(app).values())

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
        syntax_class = syntax_registry.get_syntax(app.schema, attr_type, old_entry_structural_oc)
        if not syntax_class.editable:
            ignore_attr_types.add(attr_type)

    try:
        ignore_attr_types.remove('2.5.4.0')
    except KeyError:
        pass

    # Create modlist containing deltas
    modlist = modify_modlist2(
        app.schema,
        old_entry, new_entry,
        ignore_attr_types=ignore_attr_types,
        ignore_oldexistent=False,
    )
    # Binary values are always replaced
    new_entry_structural_oc = new_entry.get_structural_oc()
    for attr_type in new_entry.keys():
        syntax_class = syntax_registry.get_syntax(app.schema, attr_type, new_entry_structural_oc)
        if (not syntax_class.editable) and \
           new_entry[attr_type] and \
           (not attr_type in old_entry or new_entry[attr_type] != old_entry[attr_type]):
            modlist.append((ldap0.MOD_REPLACE, attr_type, new_entry[attr_type]))

    if not modlist:
        # nothing to be changed
        app.simple_message(
            'Modify result',
            '<p class="SuccessMessage">No attributes modified of entry %s</p>' % (
                app.display_dn(app.dn, commandbutton=True),
            ),
            main_menu_list=web2ldap.app.gui.main_menu(app),
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
            msg=app.ldap_error_msg(e),
        )
        return

    # Display success message
    app.simple_message(
        'Modify result',
        '<p class="SuccessMessage">Modified entry %s</p><dt>LDIF change record:</dt>\n<dd>%s</dd>' % (
            app.display_dn(app.dn, commandbutton=True),
            modlist_ldif(app.dn, app.form, modlist),
        ),
        main_menu_list=web2ldap.app.gui.main_menu(app),
        context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(app)
    )
