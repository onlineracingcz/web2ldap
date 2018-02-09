# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for schema elements defined for
MS Identity Management for Unix (formerly known as MS Services for Unix)
"""

from __future__ import absolute_import

from w2lapp.schema.syntaxes import DynamicValueSelectList,syntax_registry


class MsSFU30NisDomain(DynamicValueSelectList):
  oid = 'MsSFU30NisDomain-oid'
  desc = 'Name of NIS domain controlled by MS SFU'
  ldap_url = 'ldap:///_?cn,cn?sub?(objectClass=msSFU30DomainInfo)'

syntax_registry.registerAttrType(
  MsSFU30NisDomain.oid,[
    '1.2.840.113556.1.6.18.1.339', # msSFU30NisDomain
  ]
)


# Register all syntax classes in this module
for symbol_name in dir():
  syntax_registry.registerSyntaxClass(eval(symbol_name))
