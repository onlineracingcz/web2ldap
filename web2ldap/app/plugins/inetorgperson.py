# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for selected attributes of inetOrgPerson
(see RFC 2798)

Basically some attribute values are composed from other attributes
but only if the structural object class of the entry is inetOrgPerson.
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import ComposedAttribute,DirectoryString,syntax_registry


class CNInetOrgPerson(ComposedAttribute,DirectoryString):
  oid = 'CNInetOrgPerson-oid'
  desc = 'Attribute cn in object class inetOrgPerson'
  maxValues = 1
  compose_templates = (
    '{givenName} {sn}',
  )


class DisplayNameInetOrgPerson(ComposedAttribute,DirectoryString):
  oid = 'DisplayNameInetOrgPerson-oid'
  desc = 'Attribute displayName in object class inetOrgPerson'
  maxValues = 1
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
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
