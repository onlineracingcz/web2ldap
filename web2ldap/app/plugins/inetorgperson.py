# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for selected attributes of inetOrgPerson
(see RFC 2798)

Basically some attribute values are composed from other attributes
but only if the structural object class of the entry is inetOrgPerson.
"""

from ..schema.syntaxes import ComposedAttribute, DirectoryString, syntax_registry


class CNInetOrgPerson(ComposedAttribute, DirectoryString):
    oid: str = 'CNInetOrgPerson-oid'
    desc: str = 'Attribute cn in object class inetOrgPerson'
    max_values = 1
    compose_templates = (
        '{givenName} {sn}',
    )


class DisplayNameInetOrgPerson(ComposedAttribute, DirectoryString):
    oid: str = 'DisplayNameInetOrgPerson-oid'
    desc: str = 'Attribute displayName in object class inetOrgPerson'
    max_values = 1
    compose_templates = (
        '{givenName} {sn} ({uid}/{employeeNumber})',
        '{givenName} {sn} ({uid}/{uniqueIdentifier})',
        '{givenName} {sn} ({employeeNumber})',
        '{givenName} {sn} / {ou} ({departmentNumber})',
        '{givenName} {sn} / {ou}',
        '{givenName} {sn} ({uid})',
        '{givenName} {sn}',
    )


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
