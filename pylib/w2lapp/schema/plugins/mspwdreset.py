# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for msPwdReset*
"""

from __future__ import absolute_import

from w2lapp.schema.syntaxes import \
  HashAlgorithmOID,syntax_registry


syntax_registry.registerAttrType(
  HashAlgorithmOID.oid,[
    '1.3.6.1.4.1.5427.1.389.4.336' , # msPwdResetHashAlgorithm
  ]
)
