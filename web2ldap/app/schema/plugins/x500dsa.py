# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for X.500 DSAs
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import OctetString,syntax_registry

class AccessControlInformation(OctetString):
  oid = '1.3.6.1.4.1.1466.115.121.1.1'
  desc = 'X.500: Access Control Information (ACI)'

# Register all syntax classes in this module
for name in dir():
  syntax_registry.registerSyntaxClass(eval(name))

