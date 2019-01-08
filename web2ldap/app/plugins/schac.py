# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined in SCHAC

See https://www.terena.org/activities/tf-emc2/schac.html
"""

from __future__ import absolute_import

import re,datetime
from web2ldap.app.schema.syntaxes import DirectoryString,IA5String,NumericString,CountryString,DNSDomain,NumstringDate,syntax_registry
from web2ldap.app.plugins.msperson import Gender


syntax_registry.registerAttrType(
  CountryString.oid, [
    '1.3.6.1.4.1.25178.1.2.5',  # schacCountryOfCitizenship
    '1.3.6.1.4.1.25178.1.2.11', # schacCountryOfResidence
  ]
)

syntax_registry.registerAttrType(
  DNSDomain.oid, [
    '1.3.6.1.4.1.25178.1.2.9', # schacHomeOrganization
  ]
)

class SchacMotherTongue(IA5String):
  oid = 'SchacMotherTongue-oid'
  desc = 'Language tag of the language a person learns first (see RFC 3066).'
  reObj = re.compile('^[a-zA-Z]{2,8}(-[a-zA-Z0-9]{2,8})*$')

syntax_registry.registerAttrType(
  SchacMotherTongue.oid, [
    '1.3.6.1.4.1.25178.1.2.1', # schacMotherTongue
  ]
)


syntax_registry.registerAttrType(
  Gender.oid, [
    '1.3.6.1.4.1.25178.1.2.2', # schacGender
  ]
)


class SchacDateOfBirth(NumstringDate):
  oid = 'SchacDateOfBirth-oid'
  desc = 'Date of birth: syntax YYYYMMDD'

  def _age(self,birth_dt):
    birth_date = datetime.date(year=birth_dt.year,month=birth_dt.month,day=birth_dt.day)
    current_date = datetime.date.today()
    age = current_date.year - birth_date.year
    if birth_date.month>current_date.month or \
       (birth_date.month==current_date.month and birth_date.day>current_date.day):
      age = age-1
    return age

  def _validate(self, attrValue):
    try:
      birth_dt = datetime.datetime.strptime(attrValue,self.storageFormat)
    except ValueError:
      return 0
    else:
      return self._age(birth_dt)>=0

  def displayValue(self, valueindex=False, commandbutton=False):
    raw_date = NumstringDate.displayValue(self, valueindex, commandbutton)
    try:
      birth_dt = datetime.datetime.strptime(self.attrValue,self.storageFormat)
    except ValueError:
      return raw_date
    else:
      return '%s (%s years old)' % (raw_date,self._age(birth_dt))

syntax_registry.registerAttrType(
  SchacDateOfBirth.oid, [
    '1.3.6.1.4.1.25178.1.2.3', # schacDateOfBirth
  ]
)


class SchacYearOfBirth(NumericString):
  oid = 'SchacYearOfBirth-oid'
  desc = 'Year of birth: syntax YYYY'
  maxLen = 4
  reObj = re.compile('^[0-9]{4}$')

  def _validate(self, attrValue):
    try:
      birth_year = int(attrValue)
    except ValueError:
      return 0
    else:
      return birth_year<=datetime.date.today().year

syntax_registry.registerAttrType(
  SchacYearOfBirth.oid, [
    '1.3.6.1.4.1.25178.1.0.2.3', # schacYearOfBirth
  ]
)


class SchacUrn(DirectoryString):
  oid = 'SchacUrn-oid'
  desc = 'Generic URN for SCHAC'
  reObj = re.compile('^urn:mace:terena.org:schac:.+$')

syntax_registry.registerAttrType(
  SchacUrn.oid, [
    '1.3.6.1.4.1.25178.1.2.10', # schacHomeOrganizationType
    '1.3.6.1.4.1.25178.1.2.13', # schacPersonalPosition
    '1.3.6.1.4.1.25178.1.2.14', # schacPersonalUniqueCode
    '1.3.6.1.4.1.25178.1.2.15', # schacPersonalUniqueID
    '1.3.6.1.4.1.25178.1.2.19', # schacUserStatus
  ]
)


# Register all syntax classes in this module
for symbol_name in dir():
  syntax_registry.registerSyntaxClass(eval(symbol_name))
