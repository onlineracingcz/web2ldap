# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for ASN.1 objects
"""

from __future__ import absolute_import

from w2lapp.schema.syntaxes import ASN1Object,syntax_registry


syntax_registry.registerAttrType(
  ASN1Object.oid,[
    '1.3.6.1.4.1.8301.3.6.1.1', # signatureRenewal
    '1.3.6.1.4.1.8301.3.6.1.2', # signatureRenewals
    '0.2.262.1.10.7.124', # signatureRenewals
  ]
)


# Register all syntax classes in this module
for symbol_name in dir():
  syntax_registry.registerSyntaxClass(eval(symbol_name))
