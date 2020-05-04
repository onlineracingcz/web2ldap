# -*- coding: utf-8 -*-
"""
web2ldap.app.read: Read single entry and output as HTML or vCard

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2020 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from collections import UserDict

import ldap0.schema
from ldap0.cidict import CIDict
from ldap0.schema.models import SchemaElementOIDSet, AttributeType
from ldap0.schema.subentry import SubSchema
from ldap0.base import encode_entry_dict
from ldap0.dn import DNObj

import web2ldap.web.forms
import web2ldap.app.core
import web2ldap.app.cnf
import web2ldap.app.gui
import web2ldap.app.schema
from web2ldap.app.schema.syntaxes import syntax_registry
from web2ldap.msbase import GrabKeys
from web2ldap.app.schema.viewer import schema_anchor


class VCardEntry(UserDict):

    def __init__(self, app, entry, out_charset='utf-8'):
        self._app = app
        self._entry = entry
        self._out_charset = out_charset

    def __contains__(self, nameoroid):
        return self._entry.__contains__(nameoroid)

    def __getitem__(self, nameoroid):
        if web2ldap.app.schema.no_humanreadable_attr(self._app.schema, nameoroid):
            raise KeyError('Not human-readable attribute %r not usable in vCard' % (nameoroid,))
        value = self._entry.__getitem__(nameoroid)[0]
        return value.decode(self._app.ls.charset)


def get_vcard_template(app, object_classes):
    template_dict = CIDict(app.cfg_param('vcard_template', {}))
    current_oc_set = {s.lower().decode('ascii') for s in object_classes}
    template_oc = list(current_oc_set.intersection(template_dict.data.keys()))
    if not template_oc:
        return None
    return web2ldap.app.gui.GetVariantFilename(template_dict[template_oc[0]], app.form.accept_language)


def generate_vcard(template_str, vcard_entry):
    res = []
    for line in template_str.decode('utf-8').split('\n'):
        try:
            res_line = line % vcard_entry
        except KeyError:
            pass
        else:
            res.append(res_line.strip())
    return '\r\n'.join(res)


class DisplayEntry(UserDict):

    def __init__(self, app, dn, schema, entry, sep_attr, commandbutton):
        assert isinstance(dn, str), TypeError("Argument 'dn' must be str, was %r" % (dn))
        assert isinstance(schema, SubSchema), \
            TypeError('Expected schema to be instance of SubSchema, was %r' % (schema))
        self._app = app
        self.schema = schema
        self._set_dn(dn)
        if isinstance(entry, dict):
            self.entry = ldap0.schema.models.Entry(schema, dn, entry)
        elif isinstance(entry, ldap0.schema.models.Entry):
            self.entry = entry
        else:
            raise TypeError(
                'Invalid type of argument entry, was %s.%s %r' % (
                    entry.__class__.__module__,
                    entry.__class__.__name__,
                    entry,
                )
            )
        self.soc = self.entry.get_structural_oc()
        self.invalid_attrs = set()
        self.sep_attr = sep_attr
        self.commandbutton = commandbutton

    def __getitem__(self, nameoroid):
        try:
            values = self.entry.__getitem__(nameoroid)
        except KeyError:
            return ''
        result = []
        syntax_se = syntax_registry.get_syntax(self.entry._s, nameoroid, self.soc)
        for i, value in enumerate(values):
            attr_instance = syntax_se(
                self._app,
                self.dn,
                self.entry._s,
                nameoroid,
                value,
                self.entry,
            )
            try:
                attr_value_html = attr_instance.display(
                    valueindex=i,
                    commandbutton=self.commandbutton,
                )
            except UnicodeError:
                # Fall back to hex-dump output
                attr_instance = web2ldap.app.schema.syntaxes.OctetString(
                    self._app,
                    self.dn,
                    self.schema,
                    nameoroid,
                    value,
                    self.entry,
                )
                attr_value_html = attr_instance.display(
                    valueindex=i,
                    commandbutton=True,
                )
            try:
                attr_instance.validate(value)
            except web2ldap.app.schema.syntaxes.LDAPSyntaxValueError:
                attr_value_html = '<s>%s</s>' % (attr_value_html)
                self.invalid_attrs.add(nameoroid)
            result.append(attr_value_html)
        if self.sep_attr is not None:
            value_sep = getattr(attr_instance, self.sep_attr)
            return value_sep.join(result)
        return result

    def _get_rdn_dict(self, dn):
        assert isinstance(dn, str), TypeError("Argument 'dn' must be str, was %r" % (dn))
        entry_rdn_dict = ldap0.schema.models.Entry(
            self.schema,
            dn,
            encode_entry_dict(DNObj.from_str(dn).rdn_attrs()),
        )
        for attr_type, attr_values in list(entry_rdn_dict.items()):
            del entry_rdn_dict[attr_type]
            d = ldap0.cidict.CIDict()
            for attr_value in attr_values:
                assert isinstance(attr_value, bytes), \
                    TypeError("Var 'attr_value' must be bytes, was %r" % (attr_value))
                d[attr_value] = None
            entry_rdn_dict[attr_type] = d
        return entry_rdn_dict

    def _set_dn(self, dn):
        self.dn = dn
        self.rdn_dict = self._get_rdn_dict(dn)
        # end of _set_dn()

    def get_html_templates(self, cnf_key):
        read_template_dict = CIDict(self._app.cfg_param(cnf_key, {}))
        # This gets all object classes no matter what
        all_object_class_oid_set = self.entry.object_class_oid_set()
        # Initialize the set with only the STRUCTURAL object class of the entry
        object_class_oid_set = SchemaElementOIDSet(
            self.entry._s, ldap0.schema.models.ObjectClass, []
        )
        structural_oc = self.entry.get_structural_oc()
        if structural_oc:
            object_class_oid_set.add(structural_oc)
        # Now add the other AUXILIARY and ABSTRACT object classes
        for oc in all_object_class_oid_set:
            oc_obj = self.entry._s.get_obj(ldap0.schema.models.ObjectClass, oc)
            if oc_obj is None or oc_obj.kind != 0:
                object_class_oid_set.add(oc)
        template_oc = object_class_oid_set.intersection(read_template_dict.data.keys())
        return template_oc.names, read_template_dict
        # end of get_html_templates()

    def template_output(self, cnf_key, display_duplicate_attrs=True):
        # Determine relevant HTML templates
        template_oc, read_template_dict = self.get_html_templates(cnf_key)
        # Sort the object classes by object class category
        structural_oc, abstract_oc, auxiliary_oc = web2ldap.app.schema.object_class_categories(
            self.entry._s,
            template_oc,
        )
        # Templates defined => display the entry with the help of the template
        used_templates = set()
        displayed_attrs = set()
        error_msg = None
        for oc_set in (structural_oc, abstract_oc, auxiliary_oc):
            for oc in oc_set:
                try:
                    read_template_filename = read_template_dict[oc]
                except KeyError:
                    error_msg = 'Template file not found'
                    continue
                read_template_filename = web2ldap.app.gui.GetVariantFilename(
                    read_template_filename,
                    self._app.form.accept_language,
                )
                if read_template_filename in used_templates:
                    # template already processed
                    continue
                used_templates.add(read_template_filename)
                if not read_template_filename:
                    error_msg = 'Empty template filename'
                    continue
                try:
                    with open(read_template_filename, 'rb') as template_file:
                        template_str = template_file.read().decode('utf-8')
                except IOError:
                    error_msg = 'I/O error reading template file'
                    continue
                template_attr_oid_set = {
                    self.entry._s.get_oid(ldap0.schema.models.AttributeType, attr_type_name)
                    for attr_type_name in GrabKeys(template_str)()
                }
                if display_duplicate_attrs or not displayed_attrs.intersection(template_attr_oid_set):
                    self._app.outf.write(template_str % self)
                    displayed_attrs.update(template_attr_oid_set)
        if error_msg:
            self._app.outf.write(
                '<p class="ErrorMessage">%s! (object class <var>%r</var>)</p>' % (
                    error_msg,
                    oc,
                )
            )
        return displayed_attrs # template_output()


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
    if u'*' in read_expandattr_set:
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
        attr_type_anchor_id = 'readattr_%s' % app.form.utf2display(attr_type_name)
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
        if web2ldap.app.schema.no_humanreadable_attr(app.schema, attr_type_name):
            if not web2ldap.app.schema.no_userapp_attr(app.schema, attr_type_name):
                dt_list.append(app.anchor(
                    'delete', 'Delete',
                    [('dn', app.dn), ('delete_attr', attr_type_name)]
                ))
            dt_list.append(app.anchor(
                'read', 'Save to disk',
                [
                    ('dn', app.dn),
                    ('read_attr', attr_type_name),
                    ('read_attrmimetype', u'application/octet-stream'),
                    ('read_attrindex', u'0'),
                ],
            ))
        dt_str = '<br>'.join(dt_list)
        app.outf.write(
            (
                '<tr class="ReadAttrTableRow">'
                '<td class="ReadAttrType" rowspan="%d">\n%s\n</td>\n'
                '<td class="ReadAttrValue">%s</td></tr>'
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

    read_output = app.form.getInputValue('read_output', [u'template'])[0]
    filterstr = app.form.getInputValue('filterstr', [u'(objectClass=*)'])[0]

    read_nocache = int(app.form.getInputValue('read_nocache', [u'0'])[0] or '0')

    # Specific attributes requested with form parameter read_attr?
    wanted_attr_set = SchemaElementOIDSet(
        app.schema,
        ldap0.schema.models.AttributeType,
        app.form.getInputValue('read_attr', app.ldap_url.attrs or []),
    )
    wanted_attrs = wanted_attr_set.names

    # Specific attributes requested with form parameter search_attrs?
    search_attrs = app.form.getInputValue('search_attrs', [u''])[0]
    if search_attrs:
        wanted_attrs.extend([
            a.strip() for a in search_attrs.split(',')
        ])

    # Determine how to get all attributes including the operational attributes
    if not wanted_attrs:
        if app.ls.supportsAllOpAttr:
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
        raise web2ldap.app.core.ErrorExit(u'Empty search result.')

    entry = ldap0.schema.models.Entry(app.schema, app.dn, search_result.entry_as)

    requested_attrs = SchemaElementOIDSet(app.schema, AttributeType, app.cfg_param('requested_attrs', []))
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

    display_entry = DisplayEntry(app, app.dn, app.schema, entry, 'readSep', 1)

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
                raise web2ldap.app.core.ErrorExit(
                    u'Attribute <em>%s</em> not in entry.' % (
                        app.form.utf2display(attr_type)
                    )
                )

        # Send a single binary attribute with appropriate MIME-type
        read_attrindex = int(app.form.getInputValue('read_attrindex', [u'0'])[0])
        syntax_se = syntax_registry.get_syntax(app.schema, attr_type, entry.get_structural_oc())

        # We have to create an LDAPSyntax instance to be able to call its methods
        attr_instance = syntax_se(app, app.dn, app.schema, attr_type, None, entry)
        # Send HTTP header with appropriate MIME type
        web2ldap.app.gui.Header(
            app,
            app.form.getInputValue(
                'read_attrmimetype',
                [attr_instance.mimeType],
            )[0],
            app.form.accept_charset,
            more_headers=[
                (
                    'Content-Disposition',
                    'inline; filename=web2ldap-export.%s' % (attr_instance.fileExt,)
                ),
            ]
        )
        # send attribute value
        app.outf.write_bytes(entry[attr_type][read_attrindex])

        return # end of single attribute display

    if read_output in {u'table', u'template'}:

        # Display the whole entry with all its attributes
        web2ldap.app.gui.top_section(
            app,
            '',
            web2ldap.app.gui.main_menu(app),
            context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(
                app,
                vcard_link=not get_vcard_template(app, entry.get('objectClass', [])) is None,
                dds_link=b'dynamicObject' in entry.get('objectClass', []),
                entry_uuid=entry['entryUUID'][0].decode(app.ls.charset) if 'entryUUID' in entry else None
            )
        )

        export_field = web2ldap.app.form.ExportFormatSelect()
        export_field.charset = app.form.accept_charset

        # List of already displayed attributes
        app.outf.write('%s\n' % (
            app.form_html(
                'search', 'Export', 'GET',
                [
                    ('dn', app.dn),
                    ('scope', u'0'),
                    ('filterstr', u'(objectClass=*)'),
                    ('search_resnumber', u'0'),
                    ('search_attrs', u','.join(map(str, wanted_attrs or []))),
                ],
                extrastr='\n'.join((
                    export_field.input_html(),
                    'Incl. op. attrs.:',
                    web2ldap.app.form.InclOpAttrsCheckbox().input_html(),
                )),
                target='web2ldapexport',
            ),
        ))

        displayed_attrs = set()

        if read_output == u'template':
            # Display attributes with HTML templates
            displayed_attrs.update(display_entry.template_output('read_template'))

        # Display the DN if no templates were used above
        if not displayed_attrs:
            if not app.dn:
                h1_display_name = u'Root DSE'
            else:
                h1_display_name = entry.get(
                    'displayName',
                    entry.get('cn', [b''])
                )[0].decode(app.ls.charset) or str(app.dn_obj.slice(0, 1))
            app.outf.write(
                '<h1>{0}</h1>\n<p class="EntryDN">{1}</p>\n'.format(
                    app.form.utf2display(h1_display_name),
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
        display_entry.sep_attr = 'readSep'

        app.outf.write(
            """%s\n%s\n%s<p>\n%s\n
            <input type=submit value="Request"> attributes:
            <input name="search_attrs" value="%s" size="40" maxlength="255">
            </p></form>
            """ % (
                app.begin_form('read', 'GET'),
                app.form.hiddenFieldHTML('read_nocache', u'1', u''),
                app.form.hiddenFieldHTML('dn', app.dn, u''),
                app.form.hiddenFieldHTML('read_output', read_output, u''),
                ','.join([
                    app.form.utf2display(at, sp_entity='  ')
                    for at in (
                        wanted_attrs
                        or {False:['*'], True:['*', '+']}[app.ls.supportsAllOpAttr]
                    )
                ])
            )
        )

        web2ldap.app.gui.footer(app)

    elif read_output == 'vcard':

        ##############################################################
        # vCard export
        ##############################################################

        vcard_template_filename = get_vcard_template(app, entry.get('objectClass', []))

        if not vcard_template_filename:
            raise web2ldap.app.core.ErrorExit(u'No vCard template file found for object class(es) of this entry.')

        # Templates defined => display the entry with the help of a template
        try:
            template_str = open(vcard_template_filename, 'rb').read()
        except IOError:
            raise web2ldap.app.core.ErrorExit(u'I/O error during reading vCard template file!')

        vcard_filename = u'web2ldap-vcard'
        for vcard_name_attr in ('displayName', 'cn', 'o'):
            try:
                vcard_filename = entry[vcard_name_attr][0].decode(app.ls.charset)
            except (KeyError, IndexError):
                pass
            else:
                break
        entry['dn'] = [app.ldap_dn]
        display_entry = VCardEntry(app, entry)
        web2ldap.app.gui.Header(
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
        app.outf.write(generate_vcard(template_str, display_entry))
