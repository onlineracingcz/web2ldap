# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined eduPerson

See http://middleware.internet2.edu/eduperson/
"""

from __future__ import absolute_import

import re
from web2ldap.app.schema.syntaxes import IA5String,SelectList,DynamicDNSelectList,syntax_registry


class EduPersonAffiliation(SelectList):
  oid = 'EduPersonAffiliation-oid'
  desc = 'Affiliation (see eduPerson)'

  attr_value_dict = {
    u'': u'',
    u'faculty': u'faculty',
    u'student': u'student',
    u'staff': u'staff',
    u'alum': u'alum',
    u'member': u'member',
    u'affiliate': u'affiliate',
    u'employee': u'employee',
    u'library-walk-in': u'library-walk-in',
  }

syntax_registry.registerAttrType(
  EduPersonAffiliation.oid, [
    '1.3.6.1.4.1.5923.1.1.1.1', # eduPersonAffiliation
    '1.3.6.1.4.1.5923.1.1.1.5', # eduPersonPrimaryAffiliation
  ]
)


class EduPersonScopedAffiliation(IA5String):
  oid = 'EduPersonScopedAffiliation-oid'
  desc = 'Scoped affiliation (see eduPerson)'
  reObj = re.compile('^(faculty|student|staff|alum|member|affiliate|employee|library-walk-in)@[a-zA-Z0-9.-]+$')

syntax_registry.registerAttrType(
  EduPersonScopedAffiliation.oid, [
    '1.3.6.1.4.1.5923.1.1.1.9', # eduPersonScopedAffiliation
  ]
)


class EduPersonOrgUnitDN(DynamicDNSelectList):
  oid = 'EduPersonOrgUnitDN-oid'
  desc = 'DN of associated organizational unit entry (see eduPerson)'
  ldap_url = 'ldap:///_??sub?(objectClass=organizationalUnit)'

syntax_registry.registerAttrType(
  EduPersonOrgUnitDN.oid, [
    '1.3.6.1.4.1.5923.1.1.1.4', # eduPersonOrgUnitDN
    '1.3.6.1.4.1.5923.1.1.1.8', # eduPersonPrimaryOrgUnitDN
  ]
)


class EduPersonOrgDN(DynamicDNSelectList):
  oid = 'EduPersonOrgDN-oid'
  desc = 'DN of associated organization entry (see eduPerson)'
  ldap_url = 'ldap:///_??sub?(objectClass=organization)'

syntax_registry.registerAttrType(
  EduPersonOrgDN.oid, [
    '1.3.6.1.4.1.5923.1.1.1.3', # eduPersonOrgDN
  ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
