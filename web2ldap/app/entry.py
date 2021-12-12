# -*- coding: ascii -*-
"""
web2ldap.app.entry - schema-aware Entry classes

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from collections import UserDict
from io import BytesIO

import ldap0.schema.models
from ldap0.cidict import CIDict
from ldap0.schema.models import (
    AttributeType,
    ObjectClass,
    SchemaElementOIDSet,
)
from ldap0.schema.subentry import SubSchema
from ldap0.dn import DNObj
from ldap0.ldif import LDIFWriter

import web2ldapcnf

from ..log import logger
from ..msbase import GrabKeys

from .tmpl import get_variant_filename
from .gui import HIDDEN_FIELD
from .schema import (
    NEEDS_BINARY_TAG,
    no_userapp_attr,
    object_class_categories,
)
from .schema.viewer import schema_anchor
from .schema.syntaxes import (
    LDAPSyntaxValueError,
    OctetString,
    syntax_registry,
)


INPUT_FORM_LDIF_TMPL = """
<fieldset>
  <legend>Raw LDIF data</legend>
  <textarea name="in_ldif" rows="50" cols="80" wrap="off">{value_ldif}</textarea>
  <p>
    Notes:
  </p>
  <ul>
    <li>Lines containing "dn:" will be ignored</li>
    <li>Only the first entry (until first empty line) will be accepted</li>
    <li>Maximum length is set to {value_ldifmaxbytes} bytes</li>
    <li>Allowed URL schemes: {text_ldifurlschemes}</li>
  </ul>
</fieldset>
"""


class DisplayEntry(UserDict):

    def __init__(self, app, dn, schema, entry, sep_attr, links):
        assert isinstance(dn, str), TypeError("Argument 'dn' must be str, was %r" % (dn))
        assert isinstance(schema, SubSchema), \
            TypeError('Expected schema to be instance of SubSchema, was %r' % (schema))
        self._app = app
        self.schema = schema
        self.dn = dn
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
        self.links = links

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
                attr_value_html = attr_instance.display(i, self.links)
            except UnicodeError:
                # Fall back to hex-dump output
                attr_instance = OctetString(
                    self._app,
                    self.dn,
                    self.schema,
                    nameoroid,
                    value,
                    self.entry,
                )
                attr_value_html = attr_instance.display(i, self.links)
            try:
                attr_instance.validate(value)
            except LDAPSyntaxValueError:
                attr_value_html = '<s>%s</s>' % (attr_value_html)
                self.invalid_attrs.add(nameoroid)
            result.append(attr_value_html)
        if self.sep_attr is not None:
            value_sep = getattr(attr_instance, self.sep_attr)
            return value_sep.join(result)
        return result

    @property
    def rdn_dict(self):
        return DNObj.from_str(self.dn).rdn_attrs()

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
        for ocl in all_object_class_oid_set:
            ocl_obj = self.entry._s.get_obj(ldap0.schema.models.ObjectClass, ocl)
            if ocl_obj is None or ocl_obj.kind != 0:
                object_class_oid_set.add(ocl)
        template_oc = object_class_oid_set.intersection(read_template_dict.data.keys())
        return template_oc.names, read_template_dict
        # end of get_html_templates()

    def template_output(self, cnf_key, display_duplicate_attrs=True):
        # Determine relevant HTML templates
        template_oc, read_template_dict = self.get_html_templates(cnf_key)
        # Sort the object classes by object class category
        structural_oc, abstract_oc, auxiliary_oc = object_class_categories(
            self.entry._s,
            template_oc,
        )
        # Templates defined => display the entry with the help of the template
        used_templates = set()
        displayed_attrs = set()
        for oc_set in (structural_oc, abstract_oc, auxiliary_oc):
            for ocl in oc_set:
                read_template_filename = read_template_dict[ocl]
                logger.debug('Template file name %r defined for %r', read_template_dict[ocl], ocl)
                if not read_template_filename:
                    logger.warning('Ignoring empty template file name for %r', ocl)
                    continue
                read_template_filename = get_variant_filename(
                    read_template_filename,
                    self._app.form.accept_language,
                )
                if read_template_filename in used_templates:
                    # template already processed
                    logger.debug(
                        'Skipping already processed template file name %r for %r',
                        read_template_dict[ocl],
                        ocl,
                    )
                    continue
                used_templates.add(read_template_filename)
                try:
                    with open(read_template_filename, 'rb') as template_file:
                        template_str = template_file.read().decode('utf-8')
                except IOError as err:
                    logger.error(
                        'Error reading template file %r for %r: %s',
                        read_template_dict[ocl],
                        ocl,
                        err,
                    )
                    continue
                template_attr_oid_set = {
                    self.entry._s.get_oid(ldap0.schema.models.AttributeType, attr_type_name)
                    for attr_type_name in GrabKeys(template_str)()
                }
                if (
                        display_duplicate_attrs
                        or not displayed_attrs.intersection(template_attr_oid_set)
                    ):
                    self._app.outf.write(template_str % self)
                    displayed_attrs.update(template_attr_oid_set)
        return displayed_attrs


class InputFormEntry(DisplayEntry):

    def __init__(
            self, app, dn, schema, entry,
            writeable_attr_oids,
            existing_object_classes=None,
            invalid_attrs=None
        ):
        assert isinstance(dn, str), TypeError("Argument 'dn' must be str, was {!r}".format(dn))
        DisplayEntry.__init__(self, app, dn, schema, entry, 'field_sep', False)
        self.existing_object_classes = existing_object_classes
        self.writeable_attr_oids = writeable_attr_oids
        self.invalid_attrs = invalid_attrs or {}
        new_object_classes = set(self.entry.object_class_oid_set()) - {
            self.entry._s.get_oid(ObjectClass, oc_name)
            for oc_name in existing_object_classes or []
        }
        new_attribute_types = self.entry._s.attribute_types(
            new_object_classes,
            raise_keyerror=0,
            ignore_dit_content_rule=self._app.ls.relax_rules
        )
        old_attribute_types = self.entry._s.attribute_types(
            existing_object_classes or [],
            raise_keyerror=0,
            ignore_dit_content_rule=self._app.ls.relax_rules
        )
        self.new_attribute_types_oids = set()
        self.new_attribute_types_oids.update(new_attribute_types[0].keys())
        self.new_attribute_types_oids.update(new_attribute_types[1].keys())
        for at_oid in list(old_attribute_types[0].keys())+list(old_attribute_types[1].keys()):
            try:
                self.new_attribute_types_oids.remove(at_oid)
            except KeyError:
                pass

    def _reset_input_counters(self):
        self.attr_counter = 0
        self.row_counter = 0
        # end of _reset_input_counters()

    def __getitem__(self, nameoroid):
        """
        Return HTML input field(s) for the attribute specified by nameoroid.
        """
        oid = self.entry.name2key(nameoroid)[0]
        nameoroid_se = self.entry._s.get_obj(AttributeType, nameoroid)
        syntax_class = syntax_registry.get_syntax(self.entry._s, nameoroid, self.soc)
        try:
            attr_values = self.entry.__getitem__(nameoroid)
        except KeyError:
            attr_values = []
        # Attribute value list must contain at least one element to display an input field
        attr_values = attr_values or [None]

        result = []

        # Eliminate binary attribute values from input form
        if not syntax_class.editable:
            attr_values = [b'']

        invalid_attr_indexes = set(self.invalid_attrs.get(nameoroid, []))

        for attr_index, attr_value in enumerate(attr_values):

            attr_inst = syntax_class(
                self._app, self.dn, self.entry._s, nameoroid, attr_value, self.entry,
            )
            highlight_invalid = attr_index in invalid_attr_indexes

            if (
                    # Attribute type 'objectClass' always read-only here
                    oid == '2.5.4.0'
                ) or (
                    # Attribute type 'structuralObjectClass' always read-only no matter what
                    oid == '2.5.21.9'
                ) or (
                    # Check whether the server indicated this attribute
                    # not to be writeable by bound identity
                    not self.writeable_attr_oids is None and
                    not oid in self.writeable_attr_oids and
                    not oid in self.new_attribute_types_oids
                ) or (
                    # Check whether attribute type/value is used in the RDN => not writeable
                    self.existing_object_classes and
                    attr_value and
                    nameoroid in self.rdn_dict and
                    self.rdn_dict[nameoroid].encode('utf-8') == attr_value
                ) or (
                    # Set to writeable if relax rules control is in effect
                    # and attribute is NO-USER-APP in subschema
                    not self._app.ls.relax_rules and
                    no_userapp_attr(self.entry._s, oid)
                ):
                result.append('\n'.join((
                    '<span class="InvalidInput">'*highlight_invalid,
                    self._app.form.hidden_field_html('in_at', nameoroid, ''),
                    HIDDEN_FIELD % ('in_avi', str(self.attr_counter), ''),
                    HIDDEN_FIELD % (
                        'in_av',
                        self._app.form.s2d(attr_inst.form_value(), sp_entity='  '),
                        self._app.form.s2d(attr_inst.form_value(), sp_entity='&nbsp;&nbsp;')
                    ),
                    '</span>'*highlight_invalid,
                )))
                self.row_counter += 1

            else:
                attr_title = ''
                attr_type_tags = []
                attr_type_name = str(nameoroid).split(';')[0]
                if nameoroid_se:
                    attr_type_name = (nameoroid_se.names or [nameoroid_se.oid])[0]
                    try:
                        attr_title = (nameoroid_se.desc or '')
                    except UnicodeError:
                        # This happens sometimes because of wrongly encoded schema files
                        attr_title = ''
                    # Determine whether transfer syntax has to be specified with ;binary
                    if (
                            nameoroid.endswith(';binary') or
                            oid in NEEDS_BINARY_TAG or
                            nameoroid_se.syntax in NEEDS_BINARY_TAG
                        ):
                        attr_type_tags.append('binary')
                input_fields = attr_inst.input_fields()
                for input_field in input_fields:
                    input_field.name = 'in_av'
                    input_field.charset = self._app.form.accept_charset
                    result.append('\n'.join([
                        '<span class="InvalidInput">'*highlight_invalid,
                        HIDDEN_FIELD % (
                            'in_at',
                            ';'.join([attr_type_name]+attr_type_tags),
                            ''
                        ),

                        HIDDEN_FIELD % ('in_avi', str(self.attr_counter), ''),
                        input_field.input_html(
                            id_value='_'.join((
                                'inputattr', attr_type_name, str(attr_index)
                            )),
                            title=attr_title
                        ),
                        attr_inst.value_button(self._app.command, self.row_counter, '+'),
                        attr_inst.value_button(self._app.command, self.row_counter, '-'),
                        '</span>'*highlight_invalid,
                    ]))
                    self.row_counter += 1

            self.attr_counter += 1

        return '<a class="hide" id="in_a_%s"></a>%s' % (
            self._app.form.s2d(nameoroid),
            '\n<br>\n'.join(result),
        )

    def attribute_types(self):
        # Initialize a list of assertions for filtering attribute types
        # displayed in the input form
        attr_type_filter = [
            ('no_user_mod', [0]),
            #('usage', range(2)),
            ('collective', [0]),
        ]
        # Check whether Manage DIT control is in effect,
        # filter out OBSOLETE attribute types otherwise
        if not self._app.ls.relax_rules:
            attr_type_filter.append(('obsolete', [0]))

        # Filter out extensibleObject
        object_class_oids = self.entry.object_class_oid_set()
        try:
            object_class_oids.remove('1.3.6.1.4.1.1466.101.120.111')
        except KeyError:
            pass
        try:
            object_class_oids.remove('extensibleObject')
        except KeyError:
            pass

        required_attrs_dict, allowed_attrs_dict = self.entry._s.attribute_types(
            list(object_class_oids),
            attr_type_filter=attr_type_filter,
            raise_keyerror=0,
            ignore_dit_content_rule=self._app.ls.relax_rules,
        )

        # Additional check whether to explicitly add object class attribute.
        # This is a work-around for LDAP servers which mark the
        # objectClass attribute as not modifiable (e.g. MS Active Directory)
        if '2.5.4.0' not in required_attrs_dict and '2.5.4.0' not in allowed_attrs_dict:
            required_attrs_dict['2.5.4.0'] = self.entry._s.get_obj(ObjectClass, '2.5.4.0')
        return required_attrs_dict, allowed_attrs_dict

    def fieldset_table(self, attr_types_dict, fieldset_title):
        self._app.outf.write(
            """<fieldset title="%s">
            <legend>%s</legend>
            <table summary="%s">
            """ % (fieldset_title, fieldset_title, fieldset_title)
        )
        seen_attr_type_oids = ldap0.cidict.CIDict()
        attr_type_names = ldap0.cidict.CIDict()
        for atype in self.entry.keys():
            at_oid = self.entry.name2key(atype)[0]
            if at_oid in attr_types_dict:
                seen_attr_type_oids[at_oid] = None
                attr_type_names[atype] = None
        for at_oid, at_se in attr_types_dict.items():
            if (
                    at_se and
                    at_oid not in seen_attr_type_oids and
                    not no_userapp_attr(self.entry._s, at_oid)
                ):
                attr_type_names[(at_se.names or (at_se.oid,))[0]] = None
        attr_types = list(attr_type_names.keys())
        attr_types.sort(key=str.lower)
        for attr_type in attr_types:
            attr_type_name = schema_anchor(self._app, attr_type, AttributeType, link_text='&raquo')
            attr_value_field_html = self[attr_type]
            self._app.outf.write(
                '<tr>\n<td class="InputAttrType">\n%s\n</td>\n<td>\n%s\n</td>\n</tr>\n' % (
                    attr_type_name,
                    attr_value_field_html,
                )
            )
        self._app.outf.write('</table>\n</fieldset>\n')
        # end of fieldset_table()

    def table_input(self, attrs_dict_list):
        self._reset_input_counters()
        for attr_dict, fieldset_title in attrs_dict_list:
            if attr_dict:
                self.fieldset_table(attr_dict, fieldset_title)
        # end of table_input()

    def template_output(self, cnf_key, display_duplicate_attrs=True):
        self._reset_input_counters()
        displayed_attrs = DisplayEntry.template_output(
            self, cnf_key, display_duplicate_attrs=display_duplicate_attrs
        )
        # Output hidden fields for attributes not displayed in template-based input form
        for attr_type, attr_values in self.entry.items():
            at_oid = self.entry.name2key(attr_type)[0]
            syntax_class = syntax_registry.get_syntax(self.entry._s, attr_type, self.soc)
            if syntax_class.editable and \
               not no_userapp_attr(self.entry._s, attr_type) and \
               not at_oid in displayed_attrs:
                for attr_value in attr_values:
                    attr_inst = syntax_class(
                        self._app, self.dn, self.entry._s, attr_type, attr_value, self.entry
                    )
                    self._app.outf.write(self._app.form.hidden_field_html('in_at', attr_type, ''))
                    self._app.outf.write(HIDDEN_FIELD % ('in_avi', str(self.attr_counter), ''))
                    try:
                        attr_value_html = self._app.form.s2d(attr_inst.form_value(), sp_entity='  ')
                    except UnicodeDecodeError:
                        # Simply display an empty string if anything goes wrong with Unicode
                        # decoding (e.g. with binary attributes)
                        attr_value_html = ''
                    self._app.outf.write(HIDDEN_FIELD % (
                        'in_av', attr_value_html, ''
                    ))
                    self.attr_counter += 1
        return displayed_attrs # template_output()

    def ldif_input(self):
        bio = BytesIO()
        ldif_writer = LDIFWriter(bio)
        ldap_entry = {}
        for attr_type in self.entry.keys():
            attr_values = self.entry.__getitem__(attr_type)
            if not no_userapp_attr(self.entry._s, attr_type):
                ldap_entry[attr_type.encode('ascii')] = [
                    attr_value
                    for attr_value in attr_values
                    if attr_value
                ]
        ldif_writer.unparse(self.dn.encode(self._app.ls.charset), ldap_entry)
        self._app.outf.write(
            INPUT_FORM_LDIF_TMPL.format(
                value_ldif=self._app.form.s2d(
                    bio.getvalue().decode('utf-8'),
                    sp_entity='  ',
                    lf_entity='\n',
                ),
                value_ldifmaxbytes=web2ldapcnf.ldif_maxbytes,
                text_ldifurlschemes=', '.join(web2ldapcnf.ldif_url_schemes)
            )
        )
        # end of ldif_input()
