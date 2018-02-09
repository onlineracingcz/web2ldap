# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for DE-Mail
"""

from __future__ import absolute_import

import os.path,web2ldapcnf

from web2ldap.app.schema.syntaxes import PropertiesSelectList,syntax_registry


class DemailMaxAuthLevel(PropertiesSelectList):
  oid = 'DemailMaxAuthLevel-oid'
  desc = 'Maximum authentication level of person/user in DE-Mail'
  properties_pathname = os.path.join(
    web2ldapcnf.etc_dir,
    'web2ldap','properties','attribute_select_demailMaxAuthLevel.properties'
  )

syntax_registry.registerAttrType(
  DemailMaxAuthLevel.oid,[
    '1.3.6.1.4.1.7924.2.1.1.1', # demailMaxAuthLevel
  ]
)


# Register all syntax classes in this module
for name in dir():
  syntax_registry.registerSyntaxClass(eval(name))
