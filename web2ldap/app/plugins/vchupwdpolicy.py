# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined in draft-vchu-ldap-pwd-policy
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import OnOffFlag,syntax_registry


syntax_registry.registerAttrType(
  OnOffFlag.oid, [
    '2.16.840.1.113730.3.1.102', # passwordChange, pwdAllowUserChange
    '2.16.840.1.113730.3.1.103', # passwordCheckSyntax, pwdCheckSyntax
    '2.16.840.1.113730.3.1.98',  # passwordExp
    '2.16.840.1.113730.3.1.105', # passwordLockout, pwdLockOut
    '2.16.840.1.113730.3.1.220', # passwordMustChange, pwdMustChange
    '2.16.840.1.113730.3.1.108', # passwordUnlock
  ]
)


# Register all syntax classes in this module
for name in dir():
  syntax_registry.registerSyntaxClass(eval(name))
