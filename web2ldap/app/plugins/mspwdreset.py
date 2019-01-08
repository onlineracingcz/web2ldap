# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for msPwdReset*
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import \
  HashAlgorithmOID,syntax_registry


syntax_registry.registerAttrType(
  HashAlgorithmOID.oid, [
    '1.3.6.1.4.1.5427.1.389.4.336' , # msPwdResetHashAlgorithm
  ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
