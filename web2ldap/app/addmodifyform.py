# -*- coding: utf-8 -*-
"""
web2ldap.app.addmodifyform: input form for adding and modifying an entry

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from io import BytesIO

import ldap0
import ldap0.ldif
import ldap0.schema
from ldap0.dn import DNObj
from ldap0.base import decode_list
from ldap0.schema.models import \
    AttributeType, \
    ObjectClass, \
    DITStructureRule,  \
    DITContentRule

import web2ldapcnf

from ..msbase import GrabKeys
from ..web import escape_html
from ..web.forms import Select as SelectField
from . import ErrorExit

from .schema import (
    NEEDS_BINARY_TAG,
    no_humanreadable_attr,
    no_userapp_attr,
    object_class_categories,
)
from .schema.viewer import schema_anchors
from .schema.syntaxes import syntax_registry
from .schema.syntaxes import LDAPSyntaxValueError
from .schema.viewer import schema_anchor
from .form import ObjectClassSelect
from .gui import (
    HIDDEN_FIELD,
    footer,
    main_menu,
    top_section,
)
from .entry import DisplayEntry

H1_MSG = {
    'add':'Add new entry',
    'modify':'Modify entry',
}

INPUT_FORM_BEGIN_TMPL = """

  <h1>{text_heading}</h1>

  {text_msg}

  {text_supentry}

  {form_begin}

  {field_dn}
  {field_currentformtype}

  <p>

    <input
      type="submit"
      value="Save"
    >

    Change input form:

    <button
      type="submit"
      name="in_ft"
      value="Template"
      title="Switch to HTML template input form"
    >
      Template
    </button>

    <button
      type="submit"
      name="in_ft"
      value="Table"
      title="Switch to attribute table input form"
    >
      Table
    </button>

    <button
      type="submit"
      name="in_ft"
      value="LDIF"
      title="Switch to multi-line LDIF input form"
    >
      LDIF
    </button>

    Change&nbsp;Object&nbsp;
    <button
      type="submit"
      name="in_ft"
      title="Switch to object class select form"
      value="OC">
      Classes
    </button>

  </p>
"""

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


def get_entry_input(app):

    # Get all the attribute types
    in_attrtype_list = app.form.getInputValue('in_at', [])
    # Get all the attribute values
    in_value_list = app.form.getInputValue('in_av', [])

    if not len(in_attrtype_list) == len(in_value_list):
        raise ErrorExit('Different count of attribute types and values input.')

    entry = ldap0.schema.models.Entry(app.schema, app.dn, {})

    # Stuff input field lists into raw dictionary
    for i, attr_type in enumerate(in_attrtype_list):
        attr_value = in_value_list[i]
        if isinstance(attr_value, str):
            attr_value = app.ls.uc_encode(attr_value)[0]
        try:
            entry[attr_type].append(attr_value)
        except KeyError:
            entry[attr_type] = [attr_value]

    # Convert input field string representation into potential LDAP string representation
    # sanitize 'objectClass' first
    oc_attr_instance = syntax_registry.get_at(
        app, app.dn, app.schema,
        'objectClass', None,
        entry=entry,
    )
    entry['objectClass'] = [
        oc_attr_instance.sanitize(oc)
        for oc in entry.get('objectClass', [])
    ]

    # sanitize rest of dict
    for attr_type, in_values in entry.items():
        if attr_type == '2.5.4.0':
            # ignore object class attribute herein
            continue
        attr_values = []
        for in_value in in_values:
            attr_instance = syntax_registry.get_at(
                app, app.dn, app.schema,
                attr_type, None,
                entry=entry,
            )
            assert isinstance(in_value, bytes), TypeError(
                'Expected in_value to be bytes, got %r' % (in_value,)
            )
            attr_value = attr_instance.sanitize(in_value)
            assert isinstance(attr_value, bytes), TypeError(
                'Expected %s.sanitize(%r) to return bytes, got %r' % (
                    attr_instance.__class__.__name__,
                    in_value,
                    attr_value,
                )
            )
            attr_values.append(attr_value)
        entry[attr_type] = attr_values

    # extend entry with LDIF input
    try:
        in_ldif = app.form.field['in_ldif'].ldif_records
    except ValueError as e:
        raise ErrorExit(
            'LDIF parsing error: %s' % (app.form.s2d(str(e)))
        )
    else:
        if in_ldif:
            entry.update(in_ldif[0][1])

    # Transmuting whole attribute value lists into final LDAP string
    # representation which may be an interactive result
    iteration_count = 7
    entry_changed = True
    while entry_changed and iteration_count:
        iteration_count -= 1
        entry_changed = False
        for attr_type, attr_values in entry.items():
            attr_instance = syntax_registry.get_at(
                app, app.dn, app.schema,
                attr_type, None,
                entry=entry,
            )
            new_values = attr_instance.transmute(attr_values)
            assert not attr_values or isinstance(attr_values[0], bytes), TypeError(
                'Expected %s.transmute(%r) to return list of bytes, got %r' % (
                    attr_instance.__class__.__name__,
                    attr_values,
                    new_values,
                )
            )
            entry_changed = entry_changed or (new_values != attr_values)
            entry[attr_type] = new_values

    invalid_attrs = {}

    # Checking for invalid input done after sanitizing all values so
    # plugin classes can use all entry's attributes for cross-checking input
    for attr_type, attr_values in list(entry.items()):
        attr_values = entry[attr_type]
        if not attr_values:
            del entry[attr_type]
            continue
        attr_instance = syntax_registry.get_at(
            app, app.dn, app.schema,
            attr_type, None,
            entry=entry,
        )
        for attr_index, attr_value in enumerate(attr_values):
            if attr_value:
                try:
                    attr_instance.validate(attr_value)
                except LDAPSyntaxValueError:
                    try:
                        invalid_attrs[attr_type].append(attr_index)
                    except KeyError:
                        invalid_attrs[attr_type] = [attr_index]

    return entry, invalid_attrs # get_entry_input()


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

        attr_inst = syntax_class(
            self._app, self.dn, self.entry._s, nameoroid, None, self.entry
        )
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
                    not self.writeable_attr_oids is None and \
                    not oid in self.writeable_attr_oids and \
                    not oid in self.new_attribute_types_oids
                ) or (
                    # Check whether attribute type/value is used in the RDN => not writeable
                    self.existing_object_classes and \
                    attr_value and \
                    nameoroid in self.rdn_dict and \
                    attr_value in self.rdn_dict[nameoroid]
                ) or (
                    # Set to writeable if relax rules control is in effect
                    # and attribute is NO-USER-APP in subschema
                    not self._app.ls.relax_rules and \
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
                    attr_inst.value_button(self._app.command, self.row_counter, '+'),
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
        for a in self.entry.keys():
            at_oid = self.entry.name2key(a)[0]
            if at_oid in attr_types_dict:
                seen_attr_type_oids[at_oid] = None
                attr_type_names[a] = None
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
        f = BytesIO()
        ldif_writer = ldap0.ldif.LDIFWriter(f)
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
                    f.getvalue().decode('utf-8'),
                    sp_entity='  ',
                    lf_entity='\n',
                ),
                value_ldifmaxbytes=web2ldapcnf.ldif_maxbytes,
                text_ldifurlschemes=', '.join(web2ldapcnf.ldif_url_schemes)
            )
        )
        # end of ldif_input()


def superior_display_html(
        app,
        parent_dn,
        supentry_display_tmpl=(
            '<p title="Superior entry information">'
            '<strong>Superior entry:</strong><br>'
            '{0}'
            '</p>'
        ),
    ):
    assert isinstance(parent_dn, str), TypeError(
        "Argument 'parent_dn' must be str, was %r" % (parent_dn)
    )
    if parent_dn is None:
        return ''
    supentry_display_strings = []
    inputform_supentrytemplate = app.cfg_param('inputform_supentrytemplate', {})
    if inputform_supentrytemplate:
        inputform_supentrytemplate_attrtypes = set(['objectClass'])
        for oc in inputform_supentrytemplate.keys():
            inputform_supentrytemplate_attrtypes.update(
                GrabKeys(inputform_supentrytemplate[oc]).keys
            )
        try:
            parent_search_result = app.ls.l.read_s(
                parent_dn,
                attrlist=inputform_supentrytemplate_attrtypes,
            )
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.REFERRAL,
            ):
            pass
        else:
            if parent_search_result is not None:
                parent_entry = DisplayEntry(
                    app, parent_dn, app.schema,
                    parent_search_result.entry_as, 'read_sep', 0
                )
                for oc in parent_search_result.entry_s.get('objectClass', []):
                    try:
                        inputform_supentrytemplate[oc]
                    except KeyError:
                        pass
                    else:
                        supentry_display_strings.append(
                            inputform_supentrytemplate[oc] % parent_entry
                        )
    if supentry_display_strings:
        return supentry_display_tmpl.format('\n'.join(supentry_display_strings))
    return app.form.s2d(parent_dn)


def object_class_form(
        app,
        existing_object_classes,
        structural_object_class
    ):
    """Form for choosing object class(es)"""

    def get_possible_soc(app, parent_dn):
        """
        This function tries to determine the possible structural object classes
        and returns it as a list of object class NAMEs
        """
        all_structural_oc = None
        dit_structure_rule_html = ''
        # Determine possible structural object classes based on DIT structure rules
        # and name forms if DIT structure rules are defined in subschema
        if app.schema.sed[DITStructureRule]:
            dit_structure_ruleid = app.ls.get_governing_structure_rule(parent_dn, app.schema)
            if dit_structure_ruleid is not None:
                subord_structural_ruleids, subord_structural_oc = \
                    app.schema.get_subord_structural_oc_names(dit_structure_ruleid)
                if subord_structural_oc:
                    all_structural_oc = subord_structural_oc
                    dit_structure_rule_html = 'DIT structure rules:<br>%s' % ('<br>'.join(
                        schema_anchors(
                            app,
                            subord_structural_ruleids,
                            DITStructureRule
                        )
                    ))
        # Determine possible structural object classes based on operational
        # attribute 'allowedChildClasses' (MS AD or OpenLDAP with slapo-allowed)
        elif (
                '1.2.840.113556.1.4.912' in app.schema.sed[AttributeType] and
                not app.ls.is_openldap
            ):
            try:
                parent = app.ls.l.read_s(
                    parent_dn,
                    attrlist=['allowedChildClasses', 'allowedChildClassesEffective'],
                )
            except (
                    ldap0.NO_SUCH_OBJECT,
                    ldap0.INSUFFICIENT_ACCESS,
                    ldap0.REFERRAL,
                ):
                pass
            else:
                if parent:
                    try:
                        allowed_child_classes = parent.entry_s['allowedChildClasses']
                    except KeyError:
                        dit_structure_rule_html = ''
                    else:
                        allowed_child_classes_kind_dict = {0:[], 1:[], 2:[]}
                        for av in allowed_child_classes:
                            at_se = app.schema.get_obj(ObjectClass, av)
                            if not at_se is None:
                                allowed_child_classes_kind_dict[at_se.kind].append(av)
                        all_structural_oc = allowed_child_classes_kind_dict[0]
                        #all_abstract_oc = allowed_child_classes_kind_dict[1]
                        #all_auxiliary_oc = allowed_child_classes_kind_dict[2]
                        dit_structure_rule_html = 'Governed by <var>allowedChildClasses</var>.'
        return all_structural_oc, dit_structure_rule_html
        # get_possible_soc()


    def object_class_select_fields(app, parent_dn):

        all_structural_oc, all_abstract_oc, all_auxiliary_oc = object_class_categories(
            app.schema,
            all_oc,
        )
        dit_structure_rule_html = ''

        restricted_structural_oc, dit_structure_rule_html = get_possible_soc(app, parent_dn)
        all_structural_oc = restricted_structural_oc or all_structural_oc

        existing_misc_oc = set(existing_object_classes)
        for a in existing_structural_oc+existing_abstract_oc+existing_auxiliary_oc:
            existing_misc_oc.discard(a)
        existing_misc_oc = list(existing_misc_oc)

        dit_content_rule_html = ''
        # Try to look up a DIT content rule
        if existing_object_classes and structural_object_class:
            # Determine OID of structural object class
            soc_oid = app.schema.name2oid[ObjectClass].get(
                structural_object_class,
                structural_object_class,
            )
            dit_content_rule = app.schema.get_obj(DITContentRule, soc_oid, None)
            if dit_content_rule is not None:
                if dit_content_rule.obsolete:
                    dit_content_rule_status_text = 'Ignored obsolete'
                elif app.ls.relax_rules:
                    dit_content_rule_status_text = 'Ignored'
                else:
                    dit_content_rule_status_text = 'Governed by'
                    all_auxiliary_oc_oids = {
                        app.schema.get_oid(ObjectClass, nameoroid)
                        for nameoroid in dit_content_rule.aux
                    }
                    all_auxiliary_oc = [
                        oc
                        for oc in all_auxiliary_oc
                        if app.schema.get_oid(ObjectClass, oc) in all_auxiliary_oc_oids
                    ]
                dit_content_rule_html = '%s<br>DIT content rule:<br>%s' % (
                    dit_content_rule_status_text,
                    schema_anchor(
                        app,
                        dit_content_rule.names[0],
                        DITContentRule,
                        link_text='&raquo',
                    )
                )

        abstract_select_field = ObjectClassSelect(
            name='in_oc',
            text='Abstract object class(es)',
            options=all_abstract_oc,
            default=existing_abstract_oc,
            size=20
        )
        structural_select_field = ObjectClassSelect(
            name='in_oc',
            text='Structural object class(es)',
            options=all_structural_oc,
            default=existing_structural_oc,
            size=20
        )
        auxiliary_select_field = ObjectClassSelect(
            name='in_oc',
            text='Auxiliary object class(es)',
            options=all_auxiliary_oc,
            default=existing_auxiliary_oc,
            size=20
        )
        misc_select_field = ObjectClassSelect(
            name='in_oc',
            text='Misc. object class(es)',
            options=[],
            default=existing_misc_oc,
            size=20
        )
        if existing_misc_oc:
            misc_select_field_th = '<th><label for="add_misc_oc">Misc.<label></th>'
            misc_select_field_td = '<td>%s</td>' % (
                misc_select_field.input_html(id_value='add_misc_oc')
            )
        else:
            misc_select_field_th = ''
            misc_select_field_td = ''

        input_currentformtype = app.form.getInputValue('in_oft', ['Template'])[0]

        add_structural_oc_html = structural_select_field.input_html(
            id_value='add_structural_oc',
            title='Structural object classes to be added',
        )
        add_auxiliary_oc_html = auxiliary_select_field.input_html(
            id_value='add_auxiliary_oc',
            title='Auxiliary object classes to be added',
        )
        add_abstract_oc_html = abstract_select_field.input_html(
            id_value='add_abstract_oc',
            title='Abstract object classes to be added',
        )
        add_template_field_html = """
          <p>
            <label for="input_formtype">Form type:</label> %s
            <input type="submit" value="Next &gt;&gt;">
          </p>
          <table>
            <tr>
              <th><label for="add_structural_oc">Structural</label></th>
              <th><label for="add_auxiliary_oc">Auxiliary</label></th>
              <th><label for="add_abstract_oc">Abstract</label></th>
              %s
            </tr>
            <tr>
              <td><label for="add_structural_oc">%s</label></td>
              <td><label for="add_auxiliary_oc">%s</label></td>
              <td><label for="add_abstract_oc">%s</label></td>
              %s
            </tr>
            <tr>
              <td>%s</td>
              <td>%s</td>
              <td>&nbsp;</td>
            </tr>
          </table>
        %s
        """ % (
            app.form.field['in_ft'].input_html(default=input_currentformtype),
            misc_select_field_th,
            add_structural_oc_html,
            add_auxiliary_oc_html,
            add_abstract_oc_html,
            misc_select_field_td,
            dit_structure_rule_html,
            dit_content_rule_html,
            app.form.hidden_input_html(
                ignoreFieldNames=(
                    'dn',
                    'add_clonedn',
                    'in_ocf',
                    'in_oft',
                    'in_ft',
                    'in_wrtattroids',
                )
            ),
        )
        msg = {
            'add': 'Choose object class(es) for new entry.',
            'modify': 'You may change the object class(es) for the entry.',
        }[app.command]
        msg = '<p class="WarningMessage">%s</p>' % (msg)
        return msg, add_template_field_html
        # end of object_class_select_fields()


    def ldif_template_select_html(app, parent_dn):
        all_structural_oc, _, _ = object_class_categories(app.schema, all_oc)
        addform_entry_templates_keys = list(app.cfg_param('addform_entry_templates', {}).keys())
        addform_parent_attrs = app.cfg_param('addform_parent_attrs', [])
        addform_entry_templates_keys.sort()
        add_tmpl_dict = {}
        for template_name in addform_entry_templates_keys:
            ldif_dn, ldif_entry = read_ldif_template(app, template_name)
            tmpl_parent_dn = (
                str(DNObj.from_str(ldif_dn.decode(app.ls.charset)).parent())
                or parent_dn
            )
            # first check whether mandatory attributes in parent entry are readable
            if addform_parent_attrs:
                try:
                    parent_result = app.ls.l.read_s(
                        tmpl_parent_dn,
                        attrlist=addform_parent_attrs,
                    )
                except (ldap0.NO_SUCH_OBJECT, ldap0.INSUFFICIENT_ACCESS):
                    continue
                if not parent_result:
                    continue
                parent_entry = ldap0.schema.models.Entry(
                    app.schema,
                    tmpl_parent_dn,
                    parent_result.entry_as,
                )
                missing_parent_attrs = {
                    attr_type
                    for attr_type in addform_parent_attrs
                    if attr_type not in parent_entry
                }
                if missing_parent_attrs:
                    continue
            restricted_structural_oc, _ = get_possible_soc(app, tmpl_parent_dn)
            if app.schema.sed[DITStructureRule]:
                parent_gov_structure_rule = app.ls.get_governing_structure_rule(
                    tmpl_parent_dn,
                    app.schema,
                )
                if parent_gov_structure_rule is None:
                    restricted_structural_oc = restricted_structural_oc or all_structural_oc
                else:
                    restricted_structural_oc = restricted_structural_oc or []
            else:
                restricted_structural_oc = all_structural_oc
            restricted_structural_oc_set = ldap0.schema.models.SchemaElementOIDSet(
                app.schema,
                ObjectClass,
                restricted_structural_oc
            )
            entry = ldap0.schema.models.Entry(
                app.schema,
                ldif_dn.decode(app.ls.charset),
                {at.decode('ascii'): avs for at, avs in ldif_entry.items()}
            )
            soc = entry.get_structural_oc()
            if soc and soc in restricted_structural_oc_set:
                try:
                    add_tmpl_dict[tmpl_parent_dn].append(template_name)
                except KeyError:
                    add_tmpl_dict[tmpl_parent_dn] = [template_name]
        if not add_tmpl_dict:
            return (
                '<p class="ErrorMessage">No usable LDIF templates here. Wrong %s?</p>' % (
                    app.anchor(
                        'dit', 'sub-tree',
                        [('dn', app.dn)],
                        title='browse directory tree',
                    )
                ),
                '',
            )
        add_template_html_list = ['<dl>']
        for pdn in sorted(add_tmpl_dict.keys()):
            add_template_html_list.append('<dt>%s<dt>' % (
                superior_display_html(app, pdn, supentry_display_tmpl='{0}'),
            ))
            add_template_html_list.append('<dd><ul>')
            for tmpl_name in add_tmpl_dict[pdn]:
                add_template_html_list.append(
                    '<li>%s</li>' % (
                        app.anchor(
                            'add', app.form.s2d(tmpl_name),
                            [
                                ('dn', pdn),
                                ('add_template', tmpl_name),
                                ('in_ft', 'Template'),
                            ],
                            title='Add entry beneath %s\nbased on template "%s"' % (pdn, tmpl_name),
                        )
                    )
                )
            add_template_html_list.append('</ul></dd>')
        add_template_html_list.append('</dl>')
        add_template_field_html = '\n'.join(add_template_html_list)
        msg = '<p class="WarningMessage">Choose a LDIF template and base DN for new entry</p>'
        return msg, add_template_field_html
        # end of ldif_template_select_html()


    in_ocf = app.form.getInputValue('in_ocf', ['tmpl'])[0]

    command_hidden_fields = [('dn', app.dn)]

    existing_structural_oc, existing_abstract_oc, existing_auxiliary_oc = object_class_categories(
        app.schema,
        existing_object_classes,
    )
    all_oc = [
        (app.schema.get_obj(ObjectClass, oid).names or (oid,))[0]
        for oid in app.schema.listall(ObjectClass)
    ]

    if app.command == 'add':
        parent_dn = app.dn
    elif app.command == 'modify':
        parent_dn = app.parent_dn

    # Build an select field based on config param 'addform_entry_templates'
    if app.command == 'add' and in_ocf == 'tmpl':
        msg, add_template_field_html = ldif_template_select_html(app, parent_dn)
    else:
        msg, add_template_field_html = object_class_select_fields(app, parent_dn)

    context_menu_list = []
    if app.command == 'add':
        context_menu_list.extend([
            app.anchor('add', 'Templates', [('dn', app.dn), ('in_ocf', 'tmpl')]),
            app.anchor('add', 'Expert', [('dn', app.dn), ('in_ocf', 'exp')]),
        ])

    top_section(
        app,
        H1_MSG[app.command],
        main_menu(app),
        context_menu_list=context_menu_list,
        main_div_id='Input'
    )

    # Write HTML output of object class input form
    app.outf.write(
        '<h1>%s</h1>\n%s\n</form>' % (
            H1_MSG[app.command],
            '\n'.join((
                app.begin_form(app.command, 'POST'),
                ''.join([
                    app.form.hidden_field_html(param_name, param_value, '')
                    for param_name, param_value in command_hidden_fields
                ]),
                msg,
                add_template_field_html,
            ))
        )
    )
    footer(app)
    # end of object_class_form()


def read_ldif_template(app, template_name):
    addform_entry_templates = app.cfg_param('addform_entry_templates', {})
    template_name_html = escape_html(template_name)
    if template_name not in addform_entry_templates:
        raise ErrorExit('LDIF template key &quot;%s&quot; not known.' % (template_name_html))
    ldif_file_name = addform_entry_templates[template_name]
    try:
        ldif_file = None
        try:
            ldif_file = open(ldif_file_name, 'rb')
        except IOError:
            raise ErrorExit(
                'I/O error opening LDIF template for &quot;%s&quot;.' % (template_name_html)
            )
        try:
            dn, entry = list(ldap0.ldif.LDIFParser(
                ldif_file,
                ignored_attr_types=[],
                process_url_schemes=web2ldapcnf.ldif_url_schemes
            ).parse(max_entries=1))[0]
        except (IOError, ValueError):
            raise ErrorExit(
                'Value error reading/parsing LDIF template for &quot;%s&quot;.' % (
                    template_name_html
                )
            )
        except Exception:
            raise ErrorExit(
                'Other error reading/parsing LDIF template for &quot;%s&quot;.' % (
                    template_name_html
                )
            )
    finally:
        if ldif_file is not None:
            ldif_file.close()
    return dn, entry # read_ldif_template()


def gen_attribute_type_dict(app, param_name, param_default):
    """
    Build a list of attributes assumed in configuration
    to be constant while editing entry
    """
    attrs = ldap0.cidict.CIDict()
    for attr_type in app.cfg_param(param_name, param_default):
        attrs[attr_type] = attr_type
    return attrs
    # gen_attribute_type_dict()


def cfg_constant_attributes(app):
    """
    Build a list of attributes assumed in configuration
    to be constant while editing entry
    """
    return gen_attribute_type_dict(
        app,
        'modify_constant_attrs',
        ['createTimestamp', 'modifyTimestamp', 'creatorsName', 'modifiersName'],
    )


def gen_assertion_filter(app, entry):
    filter_list = []
    for attr_type in cfg_constant_attributes(app).values():
        try:
            attr_values = entry[attr_type]
        except KeyError:
            continue
        else:
            filter_list.extend([
                '(%s)' % (
                    '='.join((
                        attr_type,
                        ldap0.filter.escape_str(attr_value.decode(app.ls.charset)),
                    ))
                )
                for attr_value in attr_values
                if attr_value is not None
            ])
    if filter_list:
        res = '(&%s)' % ''.join(filter_list)
    else:
        res = '(objectClass=*)'
    return res
    # end of gen_assertion_filter()


def nomatching_attrs(sub_schema, entry, allowed_attrs_dict, required_attrs_dict):
    """
    Determine attributes which does not appear in the schema but
    do exist in the entry
    """
    nomatching_attrs_dict = ldap0.cidict.CIDict()
    for at_name in entry.entry.keys():
        try:
            at_oid = sub_schema.name2oid[AttributeType][at_name]
        except KeyError:
            nomatching_attrs_dict[at_name] = None
        else:
            if not (
                    at_oid in allowed_attrs_dict or
                    at_oid in required_attrs_dict or
                    at_name.lower() == 'objectclass'
                ):
                nomatching_attrs_dict[at_oid] = sub_schema.get_obj(AttributeType, at_oid)
    return nomatching_attrs_dict # nomatching_attrs()


WRITEABLE_ATTRS_NONE = None
WRITEABLE_ATTRS_SLAPO_ALLOWED = 1
WRITEABLE_ATTRS_GET_EFFECTIVE_RIGHTS = 2

def read_old_entry(app, dn, sub_schema, assertion_filter, read_attrs=None):
    """
    Retrieve all editable attribute types an entry
    """

    server_ctrls = []

    # Build a list of attributes to be requested
    if not read_attrs:
        read_attrs = ldap0.cidict.CIDict({'*': '*'})
        read_attrs.update(cfg_constant_attributes(app))
        read_attrs.update(gen_attribute_type_dict(app, 'requested_attrs', []))

    # Try to request information about which attributes are writeable by the bound identity

    # Try to query attribute allowedAttributesEffective
    if '1.2.840.113556.1.4.914' in sub_schema.sed[AttributeType]:
        # Query with attribute 'allowedAttributesEffective'
        # e.g. on MS AD or OpenLDAP with slapo-allowed
        read_attrs['allowedAttributesEffective'] = 'allowedAttributesEffective'
        write_attrs_method = WRITEABLE_ATTRS_SLAPO_ALLOWED

    else:
        write_attrs_method = WRITEABLE_ATTRS_NONE

    assert write_attrs_method in {
        WRITEABLE_ATTRS_NONE, WRITEABLE_ATTRS_SLAPO_ALLOWED, WRITEABLE_ATTRS_GET_EFFECTIVE_RIGHTS
    }, ValueError('Invalid value for write_attrs_method')

    # Explicitly request attribute 'ref' if in manage DSA IT mode
    if app.ls.manage_dsa_it:
        read_attrs['ref'] = 'ref'

    # Read the editable attribute values of entry
    ldap_res = app.ls.l.read_s(
        dn,
        attrlist=read_attrs.values(),
        filterstr=assertion_filter or '(objectClass=*)',
        cache_ttl=-1.0,
        req_ctrls=server_ctrls or None,
    )
    if ldap_res is None:
        raise ldap0.NO_SUCH_OBJECT('Empty search result.')

    entry = ldap0.schema.models.Entry(sub_schema, ldap_res.dn_s, ldap_res.entry_as)

    if write_attrs_method == WRITEABLE_ATTRS_NONE:
        # No method to determine writeable attributes was used
        writeable_attr_oids = None

    elif write_attrs_method == WRITEABLE_ATTRS_SLAPO_ALLOWED:
        # Determine writeable attributes from attribute 'allowedAttributesEffective'
        try:
            writeable_attr_oids = ldap0.schema.models.SchemaElementOIDSet(
                sub_schema, AttributeType,
                [
                    aval.decode('ascii')
                    for aval in ldap_res.entry_as.get('allowedAttributesEffective', [])
                ]
            )
        except KeyError:
            writeable_attr_oids = set([])
        else:
            if 'allowedAttributesEffective' in entry:
                del entry['allowedAttributesEffective']

    elif write_attrs_method == WRITEABLE_ATTRS_GET_EFFECTIVE_RIGHTS:
        # Try to determine writeable attributes from attribute 'aclRights'
        acl_rights_attribute_level = [
            (a, v)
            for a, v in entry.data.items()
            if a[0] == '1.3.6.1.4.1.42.2.27.9.1.39' and a[1] == 'attributelevel'
        ]
        if acl_rights_attribute_level:
            writeable_attr_oids = set([])
            for a, v in acl_rights_attribute_level:
                try:
                    dummy1, dummy2, attr_type = a
                except ValueError:
                    pass
                else:
                    if v[0].lower().find(',write:1,') >= 0:
                        writeable_attr_oids.add(
                            sub_schema.get_oid(AttributeType, a[2]).decode('ascii')
                        )
                del entry[';'.join((dummy1, dummy2, attr_type))]

    return entry, writeable_attr_oids # read_old_entry()


def w2l_addform(app, add_rdn, add_basedn, entry, msg='', invalid_attrs=None):

    if msg:
        msg = '<p class="ErrorMessage">%s</p>' % (msg)

    input_formtype = app.form.getInputValue(
        'in_ft',
        app.form.getInputValue('in_oft', ['OC'])
    )[0]

    if 'in_oc' in app.form.input_field_names:
        # Read objectclass(es) from input form
        entry['objectClass'] = [oc.encode('ascii') for oc in app.form.field['in_oc'].value]

    if input_formtype == 'OC' or not entry:
        # Output the web page with object class input form
        object_class_form(app, decode_list(entry.get('objectClass', []), 'ascii'), None)
        return

    input_form_entry = InputFormEntry(
        app,
        app.dn,
        app.schema,
        entry,
        None,
        invalid_attrs=invalid_attrs
    )
    required_attrs_dict, allowed_attrs_dict = input_form_entry.attribute_types()
    nomatching_attrs_dict = nomatching_attrs(
        app.schema,
        input_form_entry,
        allowed_attrs_dict,
        required_attrs_dict,
    )

    rdn_options = input_form_entry.entry.get_rdn_templates()

    if rdn_options and len(rdn_options) > 0:
        # <select> field
        rdn_input_field = SelectField('add_rdn', 'RDN variants', 1, options=rdn_options)
    else:
        # Just a normal <input> text field
        rdn_input_field = app.form.field['add_rdn']
    if add_rdn:
        rdn_input_field.set_default(add_rdn)
    else:
        rdn_candidate_attr_nameoroids = [
            (required_attrs_dict[at_oid].names or (at_oid,))[0]
            for at_oid in required_attrs_dict.keys()
            if at_oid != '2.5.4.0' and not no_humanreadable_attr(app.schema, at_oid)
        ]
        if len(rdn_candidate_attr_nameoroids) == 1:
            rdn_input_field.set_default(rdn_candidate_attr_nameoroids[0]+'=')

    if app.ls.relax_rules:
        msg = ''.join((
            msg,
            '<p class="WarningMessage">'
            'Relax Rules Control enabled! Be sure you know what you are doing!'
            '</p>',
        ))

    # Check whether to fall back to table input mode
    if input_formtype == 'Template':
        template_oc, _ = input_form_entry.get_html_templates('input_template')
        if not template_oc:
            msg = ''.join((
                msg,
                '<p class="WarningMessage">No templates defined for chosen object classes.</p>'
            ))
            input_formtype = 'Table'
        elif app.ls.relax_rules:
            msg = ''.join((
                msg,
                '<p class="WarningMessage">'
                'Forced to table input because Relax Rules Control is enabled.'
                '</p>'
            ))
            input_formtype = 'Table'

    top_section(
        app,
        H1_MSG[app.command],
        main_menu(app),
        context_menu_list=[]
    )

    app.outf.write(
        INPUT_FORM_BEGIN_TMPL.format(
            text_heading=H1_MSG[app.command],
            text_msg=msg,
            text_supentry=superior_display_html(app, add_basedn),
            form_begin=app.begin_form(app.command, 'POST', enctype='multipart/form-data'),
            field_dn=app.form.hidden_field_html('dn', app.dn, ''),
            field_currentformtype=app.form.hidden_field_html('in_oft', str(input_formtype), ''),
        )
    )

    app.outf.write(
        '%s\n<p>RDN: %s</p>\n%s' % (
            app.form.hidden_field_html('add_basedn', add_basedn, ''),
            rdn_input_field.input_html(),
            app.form.hidden_field_html('in_ocf', 'exp', ''),
        )
    )

    if input_formtype == 'Template':
        input_form_entry.template_output(
            'input_template',
            display_duplicate_attrs=False
        )
    elif input_formtype == 'Table':
        input_form_entry.table_input(
            (
                (required_attrs_dict, 'Required attributes'),
                (allowed_attrs_dict, 'Allowed attributes'),
                (nomatching_attrs_dict, 'Other attributes'),
            )
        )
    elif input_formtype == 'LDIF':
        input_form_entry.ldif_input()

    app.outf.write('</form>')
    footer(app)
    # end of w2l_addform()


def w2l_modifyform(app, entry, msg='', invalid_attrs=None):

    if msg:
        msg = '<p class="ErrorMessage">%s</p>' % (msg)

    input_formtype = app.form.getInputValue(
        'in_ft',
        app.form.getInputValue('in_oft', ['Template'])
    )[0]

    if 'in_oc' in app.form.input_field_names:
        # Read objectclass(es) from input form
        entry['objectClass'] = [oc.encode('ascii') for oc in app.form.field['in_oc'].value]

    old_entry, read_writeable_attr_oids = read_old_entry(app, app.dn, app.schema, None)
    if not entry:
        entry = old_entry

    in_wrtattroids = app.form.getInputValue('in_wrtattroids', [])
    if in_wrtattroids == ['nonePseudoValue;x-web2ldap-None']:
        writeable_attr_oids = None
    elif in_wrtattroids:
        writeable_attr_oids = set(in_wrtattroids)
    else:
        writeable_attr_oids = read_writeable_attr_oids

    if input_formtype == 'OC':
        # Output the web page with object class input form
        object_class_form(
            app,
            decode_list(entry['objectClass'], 'ascii'), entry.get_structural_oc(),
        )
        return

    existing_object_classes = decode_list(entry['objectClass'][:], encoding='ascii')

    input_form_entry = InputFormEntry(
        app, app.dn, app.schema,
        entry, writeable_attr_oids, existing_object_classes, invalid_attrs=invalid_attrs
    )
    required_attrs_dict, allowed_attrs_dict = input_form_entry.attribute_types()
    nomatching_attrs_dict = nomatching_attrs(
        app.schema,
        input_form_entry,
        allowed_attrs_dict,
        required_attrs_dict,
    )

    in_wrtattroids_fields_html = '\n'.join([
        app.form.hidden_field_html('in_wrtattroids', at_name, '')
        for at_name in (
            writeable_attr_oids
            if writeable_attr_oids is not None
            else ['nonePseudoValue;x-web2ldap-None']
        )
    ])

    if app.ls.relax_rules:
        msg = ''.join((
            msg,
            '<p class="WarningMessage">'
            'Relax Rules Control enabled! Be sure you know what you are doing!'
            '</p>',
        ))

    # Check whether to fall back to table input mode
    if input_formtype == 'Template':
        template_oc, _ = input_form_entry.get_html_templates('input_template')
        if not template_oc:
            msg = ''.join((
                msg,
                '<p class="WarningMessage">No templates defined for chosen object classes.</p>',
            ))
            input_formtype = 'Table'
        elif app.ls.relax_rules:
            msg = ''.join((
                msg,
                '<p class="WarningMessage">'
                'Forced to table input because Relax Rules Control is enabled.'
                '</p>',
            ))
            input_formtype = 'Table'

    top_section(
        app,
        H1_MSG[app.command],
        main_menu(app),
        context_menu_list=[]
    )

    app.outf.write(
        INPUT_FORM_BEGIN_TMPL.format(
            text_heading=H1_MSG[app.command],
            text_msg=msg,
            text_supentry=superior_display_html(app, app.parent_dn),
            form_begin=app.begin_form(app.command, 'POST', enctype='multipart/form-data'),
            field_dn=app.form.hidden_field_html('dn', app.dn, ''),
            field_currentformtype=app.form.hidden_field_html('in_oft', input_formtype, ''),
        )
    )

    app.outf.write(
        '\n'.join((
            app.form.hidden_field_html('in_assertion', gen_assertion_filter(app, entry), ''),
            '\n'.join([
                app.form.hidden_field_html('in_oldattrtypes', at_name, '')
                for at_name in app.form.getInputValue('in_oldattrtypes', entry.keys())
            ]),
        ))
    )
    app.outf.write(in_wrtattroids_fields_html)

    if input_formtype == 'Template':
        input_form_entry.template_output(
            'input_template',
            display_duplicate_attrs=False
        )

    elif input_formtype == 'Table':
        input_form_entry.table_input(
            (
                (required_attrs_dict, 'Required attributes'),
                (allowed_attrs_dict, 'Allowed attributes'),
                (nomatching_attrs_dict, 'Other attributes'),
            )
        )

    elif input_formtype == 'LDIF':
        input_form_entry.ldif_input()

    app.outf.write('</form>')
    footer(app)
    # end of w2l_modifyform()
