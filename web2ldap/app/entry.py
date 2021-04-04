# -*- coding: utf-8 -*-
"""
web2ldap.app.entry - schema-aware Entry classes

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from collections import UserDict

import ldap0.schema.models
from ldap0.cidict import CIDict
from ldap0.schema.models import SchemaElementOIDSet
from ldap0.schema.subentry import SubSchema
from ldap0.base import encode_entry_dict
from ldap0.dn import DNObj

from ..log import logger
from ..msbase import GrabKeys

from .tmpl import get_variant_filename

from .schema import object_class_categories
from .schema.syntaxes import (
    LDAPSyntaxValueError,
    OctetString,
    syntax_registry,
)


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
                attr_instance = OctetString(
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
            except LDAPSyntaxValueError:
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
        structural_oc, abstract_oc, auxiliary_oc = object_class_categories(
            self.entry._s,
            template_oc,
        )
        # Templates defined => display the entry with the help of the template
        used_templates = set()
        displayed_attrs = set()
        for oc_set in (structural_oc, abstract_oc, auxiliary_oc):
            for oc in oc_set:
                read_template_filename = read_template_dict[oc]
                logger.debug('Template file name %r defined for %r', read_template_dict[oc], oc)
                if not read_template_filename:
                    logger.warning('Ignoring empty template file name for %r', oc)
                    continue
                read_template_filename = get_variant_filename(
                    read_template_filename,
                    self._app.form.accept_language,
                )
                if read_template_filename in used_templates:
                    # template already processed
                    logger.debug(
                        'Skipping already processed template file name %r for %r',
                        read_template_dict[oc],
                        oc,
                    )
                    continue
                used_templates.add(read_template_filename)
                try:
                    with open(read_template_filename, 'rb') as template_file:
                        template_str = template_file.read().decode('utf-8')
                except IOError as err:
                    logger.error(
                        'Error reading template file %r for %r: %s',
                        read_template_dict[oc],
                        oc,
                        err,
                    )
                    continue
                template_attr_oid_set = {
                    self.entry._s.get_oid(ldap0.schema.models.AttributeType, attr_type_name)
                    for attr_type_name in GrabKeys(template_str)()
                }
                if display_duplicate_attrs or not displayed_attrs.intersection(template_attr_oid_set):
                    self._app.outf.write(template_str % self)
                    displayed_attrs.update(template_attr_oid_set)
        return displayed_attrs
