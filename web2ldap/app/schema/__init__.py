# -*- coding: utf-8 -*-
"""
web2ldap.app.schema: Module package for application-specific schema handling

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import sys

import ldap0
import ldap0.cidict
import ldap0.schema.models
from ldap0.schema.models import \
    AttributeType, \
    ObjectClass, \
    LDAPSyntax, \
    NOT_HUMAN_READABLE_LDAP_SYNTAXES
import ldap0.schema.util
from ldap0.schema.subentry import SCHEMA_ATTR_MAPPING

from ...log import logger
from ...web import escape_html


NOT_HUMAN_READABLE_LDAP_SYNTAXES = {
    '1.3.6.1.4.1.1466.115.121.1.4',  # Audio
    '1.3.6.1.4.1.1466.115.121.1.5',  # Binary
    '1.3.6.1.4.1.1466.115.121.1.8',  # Certificate
    '1.3.6.1.4.1.1466.115.121.1.9',  # Certificate List
    '1.3.6.1.4.1.1466.115.121.1.10', # Certificate Pair
    '1.3.6.1.4.1.1466.115.121.1.23', # G3 FAX
    '1.3.6.1.4.1.1466.115.121.1.28', # JPEG
    '1.3.6.1.4.1.1466.115.121.1.49', # Supported Algorithm
    # From draft-sermersheim-nds-ldap-schema
    '2.16.840.1.113719.1.1.5.1.12',
    '2.16.840.1.113719.1.1.5.1.13',
}


# OIDs of syntaxes and attribute types which need ;binary
NEEDS_BINARY_TAG = {
    # attribute types
    '2.5.4.37', # caCertificate
    '2.5.4.36', # userCertificate
    '2.5.4.40', # crossCertificatePair
    '2.5.4.52', # supportedAlgorithms
    '2.5.4.38', # authorityRevocationList
    '2.5.4.39', # certificateRevocationList
    '2.5.4.53', # deltaRevocationList
    # LDAP syntaxes
    '1.3.6.1.4.1.1466.115.121.1.8', # Certificate
    '1.3.6.1.4.1.1466.115.121.1.9', # Certificate List
    '1.3.6.1.4.1.1466.115.121.1.10', # Certificate Pair
    '1.3.6.1.4.1.1466.115.121.1.49', # Supported Algorithm
}

# all values must be lower-case!
USERAPP_ATTRS = {
    'objectclass',
}

# all values must be lower-case!
NO_USERAPP_ATTRS = {
    'entrycsn',
}


OBSOLETE_TEMPL = {
    False: '%s',
    True: '<s>%s</s>',
}


def no_userapp_attr(schema, attr_type_name, relax_rules=False):
    """
    Returns True if the attribute type specified by the schema
    element instance attr_se is considered operational and therefore
    should not be modified by the user.

    If the attribute type is not found in the schema False is returned.
    """
    at_lower = attr_type_name.lower()
    if at_lower in USERAPP_ATTRS:
        return False
    if at_lower in NO_USERAPP_ATTRS and not relax_rules:
        return True
    attr_type_se = schema.get_obj(AttributeType, attr_type_name)
    if attr_type_se is None:
        return False
    #return attr_type_se.usage!=0 or attr_type_se.no_user_mod or attr_type_se.collective
    return attr_type_se.no_user_mod or attr_type_se.collective


def no_humanreadable_attr(schema, attr_type):
    """
    Returns True if the attribute type specified by the server's schema
    element instance attr_se cannot be displayed human readable form.
    """
    attr_type_se = schema.get_obj(AttributeType, attr_type)
    if attr_type_se is None:
        return False
    syntax_oid = getattr(attr_type_se, 'syntax', None)
    if syntax_oid is not None:
        syntax_se = schema.get_obj(LDAPSyntax, syntax_oid)
        if syntax_se is not None and syntax_se.not_human_readable:
            return True
    return (
        syntax_oid in NOT_HUMAN_READABLE_LDAP_SYNTAXES or
        attr_type.endswith(';binary')
    )


def object_class_categories(sub_schema, object_classes):
    """
    Split a list of object class identifiers (name or OID)
    into three lists of categories of object classes.
    """
    if len(object_classes) == 1:
        # Special work-around:
        # Consider a single object class without object class description in
        # schema always to be STRUCTURAL
        oc_obj = sub_schema.get_obj(ObjectClass, object_classes[0])
        if oc_obj is None:
            oc_kind = 0
        else:
            oc_kind = oc_obj.kind
        kind = [[], [], []]
        kind[oc_kind] = object_classes
    else:
        kind = [
            ldap0.cidict.CIDict(),
            ldap0.cidict.CIDict(),
            ldap0.cidict.CIDict()
        ]
        for nameoroid in object_classes:
            oc_obj = sub_schema.get_obj(ObjectClass, nameoroid)
            if oc_obj is None:
                continue
            kind[oc_obj.kind][nameoroid] = None
        for k in range(3):
            lst = sorted(kind[k].keys(), key=str.lower)
            kind[k] = lst
    return tuple(kind)


def parse_fake_schema(ldap_def):
    """
    For each configuration item try to retrieve and
    parse site-specific subschema
    """
    for k in ldap_def.cfg_data.keys():
        try:
            schema_uri = ldap_def.cfg_data[k].schema_uri
        except AttributeError:
            continue
        logger.debug('Retrieve schema for %r from %r', k, schema_uri)
        try:
            _, schema = ldap0.schema.util.urlfetch(schema_uri)
        except Exception as err:
            logger.error('Error retrieving schema from %r: %s', schema_uri, err)
            continue
        if schema is None:
            continue
        # Store the pre-parsed schema in the configuration
        ldap_def.cfg_data[k]._schema = schema
    # end of parse_fake_schema()


def schema_link_text(se_obj):
    names = [
        escape_html(name)
        for name in getattr(se_obj, 'names', (()))
    ]
    obsolete = getattr(se_obj, 'obsolete', False)
    if len(names) == 1:
        res = names[0]
    elif len(names) > 1:
        res = '{name} (alias {other_names})'.format(
            name=names[0],
            other_names=', '.join(names[1:]),
        )
    elif isinstance(se_obj, LDAPSyntax) and se_obj.desc is not None:
        res = escape_html(se_obj.desc)
    else:
        res = escape_html(se_obj.oid)
    return OBSOLETE_TEMPL[obsolete] % res


def schema_anchor(
        app,
        se_nameoroid,
        se_class,
        name_template='{name}\n{anchor}',
        link_text=None,
    ):
    """
    Return a pretty HTML-formatted string describing a schema element
    referenced by name or OID
    """
    try:
        se_obj = app.schema.get_obj(se_class, se_nameoroid, None, raise_keyerror=True)
    except KeyError:
        anchor = ''
    else:
        anchor = app.anchor(
            'oid', link_text or schema_link_text(se_obj),
            [
                ('dn', app.dn),
                ('oid', se_obj.oid),
                ('oid_class', SCHEMA_ATTR_MAPPING[se_class]),
            ]
        )
    return name_template.format(
        name=app.form.utf2display(se_nameoroid),
        anchor=anchor,
    )
    # end of schema_anchor()
