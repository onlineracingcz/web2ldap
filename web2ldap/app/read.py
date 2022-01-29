# -*- coding: ascii -*-
"""
web2ldap.app.read: Read single entry and output as HTML or vCard

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from collections import UserDict

import ldap0.dn
from ldap0.cidict import CIDict
from ldap0.schema.models import SchemaElementOIDSet, AttributeType

from .schema import no_humanreadable_attr, no_userapp_attr
from .schema.syntaxes import syntax_registry
from .schema.viewer import schema_anchor
from . import ErrorExit
from .tmpl import get_variant_filename
from .gui import (
    context_menu_single_entry,
    footer,
    header,
    main_menu,
    top_section,
)
from .form import ExportFormatSelect, InclOpAttrsCheckbox
from .entry import DisplayEntry


class VCardEntry(UserDict):

    def __init__(self, app, entry, out_charset='utf-8'):
        UserDict.__init__(self, entry)
        self._app = app
        self._out_charset = out_charset

    def __getitem__(self, nameoroid):
        if no_humanreadable_attr(self._app.schema, nameoroid):
            raise KeyError('Not human-readable attribute %r not usable in vCard' % (nameoroid,))
        return UserDict.__getitem__(self, nameoroid)[0].decode(self._app.ls.charset)

    def generate_vcard(self, template_str):
        res = []
        for line in template_str.decode('utf-8').split('\n'):
            try:
                res_line = line % self
            except KeyError:
                pass
            else:
                res.append(res_line.strip())
        return '\r\n'.join(res)


def get_vcard_template(app, object_classes):
    template_dict = CIDict(app.cfg_param('vcard_template', {}))
    current_oc_set = {s.lower().decode('ascii') for s in object_classes}
    template_oc = list(current_oc_set.intersection(template_dict.data.keys()))
    if not template_oc:
        return None
    return get_variant_filename(template_dict[template_oc[0]], app.form.accept_language)


def display_attribute_table(app, entry, attrs, comment):
    """
    Send a table of attributes to outf
    """
    # Determine which attributes are shown
    show_attrs = [
        a
        for a in attrs
        if a in entry.entry
    ]
    if not show_attrs:
        # There's nothing to display => exit
        return
    show_attrs.sort(key=str.lower)
    # Determine which attributes are shown expanded or collapsed
    read_expandattr_set = {
        at.strip().lower()
        for at in app.form.getInputValue('read_expandattr', [])
        if at
    }
    if '*' in read_expandattr_set:
        read_tablemaxcount_dict = {}
    else:
        read_tablemaxcount_dict = ldap0.cidict.CIDict(
            app.cfg_param('read_tablemaxcount', {})
        )
        for at in read_expandattr_set:
            try:
                del read_tablemaxcount_dict[at]
            except KeyError:
                pass
    app.outf.write('<h2>%s</h2>\n<table class="ReadAttrTable">' % (comment))
    # Set separation of attribute values inactive
    entry.sep = None
    for attr_type_name in show_attrs:
        attr_type_anchor_id = 'readattr_%s' % app.form.s2d(attr_type_name)
        attr_type_str = schema_anchor(
            app,
            attr_type_name,
            ldap0.schema.models.AttributeType,
            name_template='<var>{name}</var>\n{anchor}',
            link_text='&raquo;'
        )
        attr_value_disp_list = (
            entry[attr_type_name] or
            ['<strong>&lt;Empty attribute value list!&gt;</strong>']
        )
        attr_value_count = len(attr_value_disp_list)
        dt_list = [
            '<span id="%s">%s</span>\n' % (attr_type_anchor_id, attr_type_str),
        ]
        read_tablemaxcount = min(
            read_tablemaxcount_dict.get(attr_type_name, attr_value_count),
            attr_value_count,
        )
        if attr_value_count > 1:
            if attr_value_count > read_tablemaxcount:
                dt_list.append(app.anchor(
                    'read',
                    '(%d of %d values)' % (read_tablemaxcount, attr_value_count),
                    app.form.allInputFields(
                        fields=[
                            ('read_expandattr', attr_type_name),
                        ],
                    ),
                    anchor_id=attr_type_anchor_id
                ))
            else:
                dt_list.append('(%d values)' % (attr_value_count))
        if no_humanreadable_attr(app.schema, attr_type_name):
            if not no_userapp_attr(app.schema, attr_type_name):
                dt_list.append(app.anchor(
                    'delete', 'Delete',
                    [('dn', app.dn), ('delete_attr', attr_type_name)]
                ))
            dt_list.append(app.anchor(
                'read', 'Save to disk',
                [
                    ('dn', app.dn),
                    ('read_attr', attr_type_name),
                    ('read_attrmimetype', 'application/octet-stream'),
                    ('read_attrindex', '0'),
                ],
            ))
        dt_str = '<br>'.join(dt_list)
        app.outf.write(
            (
                '<tr>'
                '<th rowspan="%d">\n%s\n</th>\n'
                '<td>%s</td>'
                '</tr>'
            ) % (
                read_tablemaxcount,
                dt_str,
                attr_value_disp_list[0],
            )
        )
        if read_tablemaxcount >= 2:
            for i in range(1, read_tablemaxcount):
                app.outf.write(
                    (
                        '<tr class="ReadAttrTableRow">\n'
                        '<td class="ReadAttrValue">%s</td></tr>\n'
                    ) % (
                        attr_value_disp_list[i],
                    )
                )
    app.outf.write('</table>\n')
    return # display_attribute_table()


def w2l_read(app):

    read_output = app.form.getInputValue('read_output', ['template'])[0]
    filterstr = app.form.getInputValue('filterstr', ['(objectClass=*)'])[0]

    read_nocache = int(app.form.getInputValue('read_nocache', ['0'])[0] or '0')

    # Specific attributes requested with form parameter read_attr?
    wanted_attr_set = SchemaElementOIDSet(
        app.schema,
        ldap0.schema.models.AttributeType,
        app.form.getInputValue('read_attr', app.ldap_url.attrs or []),
    )
    wanted_attrs = wanted_attr_set.names

    # Specific attributes requested with form parameter search_attrs?
    search_attrs = app.form.getInputValue('search_attrs', [''])[0]
    if search_attrs:
        wanted_attrs.extend([
            a.strip() for a in search_attrs.split(',')
        ])

    # Determine how to get all attributes including the operational attributes
    if not wanted_attrs:
        if app.ls.supports_allop_attr:
            wanted_attrs = ['*', '+']
        else:
            wanted_attrs = []
    # Read the entry's data
    search_result = app.ls.l.read_s(
        app.dn,
        attrlist=wanted_attrs,
        filterstr=filterstr,
        cache_ttl=None if read_nocache else -1.0,
    )

    if not search_result:
        raise ErrorExit('Empty search result.')

    entry = ldap0.schema.models.Entry(app.schema, app.dn, search_result.entry_as)

    requested_attrs = SchemaElementOIDSet(
        app.schema,
        AttributeType,
        app.cfg_param('requested_attrs', []),
    )
    if not wanted_attrs and requested_attrs:
        try:
            search_result = app.ls.l.read_s(
                app.dn,
                filterstr=filterstr,
                attrlist=requested_attrs.names,
                cache_ttl=None if read_nocache else -1.0,
            )
        except (
                ldap0.NO_SUCH_ATTRIBUTE,
                ldap0.INSUFFICIENT_ACCESS,
            ):
            # Catch and ignore complaints of server about not knowing attribute
            pass
        else:
            if search_result:
                entry.update(search_result.entry_as)

    display_entry = DisplayEntry(app, app.dn, app.schema, entry, 'read_sep', 1)

    if (
            wanted_attrs
            and len(wanted_attrs) == 1
            and not wanted_attrs[0] in {b'*', b'+'}
        ):

        # Display a single binary attribute either with a registered
        # viewer or just by sending the data blob with appropriate MIME-type
        #-------------------------------------------------------------------

        attr_type = wanted_attrs[0]

        if attr_type not in entry:
            if attr_type+';binary' in entry:
                attr_type = attr_type+';binary'
            else:
                raise ErrorExit(
                    'Attribute <em>%s</em> not in entry.' % (
                        app.form.s2d(attr_type)
                    )
                )

        # Send a single binary attribute with appropriate MIME-type
        read_attrindex = int(app.form.getInputValue('read_attrindex', ['0'])[0])
        syntax_se = syntax_registry.get_syntax(app.schema, attr_type, entry.get_structural_oc())

        # We have to create an LDAPSyntax instance to be able to call its methods
        attr_instance = syntax_se(app, app.dn, app.schema, attr_type, None, entry)
        # Send HTTP header with appropriate MIME type
        header(
            app,
            app.form.getInputValue(
                'read_attrmimetype',
                [attr_instance.mime_type],
            )[0],
            app.form.accept_charset,
            more_headers=[
                (
                    'Content-Disposition',
                    'inline; filename=web2ldap-export.%s' % (attr_instance.file_ext,)
                ),
            ]
        )
        # send attribute value
        app.outf.write_bytes(entry[attr_type][read_attrindex])

        return # end of single attribute display

    if read_output in {'table', 'template'}:

        # Display the whole entry with all its attributes
        top_section(
            app,
            '',
            main_menu(app),
            context_menu_list=context_menu_single_entry(
                app,
                vcard_link=not get_vcard_template(app, entry.get('objectClass', [])) is None,
                dds_link=b'dynamicObject' in entry.get('objectClass', []),
                entry_uuid=(
                    entry['entryUUID'][0].decode(app.ls.charset)
                    if 'entryUUID' in entry
                    else None
                )
            )
        )

        export_field = ExportFormatSelect()
        export_field.charset = app.form.accept_charset

        # List of already displayed attributes
        app.outf.write('%s\n' % (
            app.form_html(
                'search', 'Export', 'GET',
                [
                    ('dn', app.dn),
                    ('scope', '0'),
                    ('filterstr', '(objectClass=*)'),
                    ('search_resnumber', '0'),
                    ('search_attrs', ','.join(map(str, wanted_attrs or []))),
                ],
                extrastr='\n'.join((
                    export_field.input_html(),
                    'Incl. op. attrs.:',
                    InclOpAttrsCheckbox().input_html(),
                )),
                target='web2ldapexport',
            ),
        ))

        displayed_attrs = set()

        if read_output == 'template':
            # Display attributes with HTML templates
            displayed_attrs.update(display_entry.template_output('read_template'))

        # Display the DN if no templates were used above
        if not displayed_attrs:
            if not app.dn:
                h1_display_name = 'Root DSE'
            else:
                h1_display_name = entry.get(
                    'displayName',
                    entry.get('cn', [b''])
                )[0].decode(app.ls.charset) or str(app.dn_obj.slice(0, 1))
            app.outf.write(
                '<h1>{0}</h1>\n<p class="EntryDN">{1}</p>\n'.format(
                    app.form.s2d(h1_display_name),
                    display_entry['entryDN'],
                )
            )


        # Display (rest of) attributes as table
        #-----------------------------------------

        required_attrs_dict, allowed_attrs_dict = entry.attribute_types(raise_keyerror=0)

        # Sort the attributes into different lists according to schema their information
        required_attrs = []
        allowed_attrs = []
        collective_attrs = []
        nomatching_attrs = []
        for a in entry.keys():
            at_se = app.schema.get_obj(ldap0.schema.models.AttributeType, a, None)
            if at_se is None:
                nomatching_attrs.append(a)
                continue
            at_oid = at_se.oid
            if at_oid in displayed_attrs:
                continue
            if at_oid in required_attrs_dict:
                required_attrs.append(a)
            elif at_oid in allowed_attrs_dict:
                allowed_attrs.append(a)
            else:
                if at_se.collective:
                    collective_attrs.append(a)
                else:
                    nomatching_attrs.append(a)

        display_entry.sep_attr = None
        display_attribute_table(app, display_entry, required_attrs, 'Required Attributes')
        display_attribute_table(app, display_entry, allowed_attrs, 'Allowed Attributes')
        display_attribute_table(app, display_entry, collective_attrs, 'Collective Attributes')
        display_attribute_table(app, display_entry, nomatching_attrs, 'Various Attributes')
        display_entry.sep_attr = 'read_sep'

        app.outf.write(
            """%s\n%s\n%s<p>\n%s\n
            <input type=submit value="Request"> attributes:
            <input name="search_attrs" value="%s" size="40" maxlength="255">
            </p></form>
            """ % (
                app.begin_form('read', 'GET'),
                app.form.hidden_field_html('read_nocache', '1', ''),
                app.form.hidden_field_html('dn', app.dn, ''),
                app.form.hidden_field_html('read_output', read_output, ''),
                ','.join([
                    app.form.s2d(at, sp_entity='  ')
                    for at in (
                        wanted_attrs
                        or {False:['*'], True:['*', '+']}[app.ls.supports_allop_attr]
                    )
                ])
            )
        )

        footer(app)

    elif read_output == 'vcard':

        ##############################################################
        # vCard export
        ##############################################################

        vcard_template_filename = get_vcard_template(app, entry.get('objectClass', []))

        if not vcard_template_filename:
            raise ErrorExit('No vCard template file found for object class(es) of this entry.')

        # Templates defined => display the entry with the help of a template
        try:
            with open(vcard_template_filename, 'rb') as fileobj:
                template_str = fileobj.read()
        except IOError:
            raise ErrorExit('I/O error during reading vCard template file!')

        vcard_filename = 'web2ldap-vcard'
        for vcard_name_attr in ('displayName', 'cn', 'o'):
            try:
                vcard_filename = entry[vcard_name_attr][0].decode(app.ls.charset)
            except (KeyError, IndexError):
                pass
            else:
                break
        entry['dn'] = [app.ldap_dn]
        display_entry = VCardEntry(app, entry)
        header(
            app,
            'text/x-vcard',
            app.form.accept_charset,
            more_headers=[
                (
                    'Content-Disposition',
                    'inline; filename={0}.vcf'.format(vcard_filename)
                ),
            ],
        )
        app.outf.write(display_entry.generate_vcard(template_str))
