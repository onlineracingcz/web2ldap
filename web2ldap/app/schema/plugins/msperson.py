# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for msPerson
"""

from __future__ import absolute_import

import re,os.path,datetime, \
       web2ldapcnf

from web2ldap.app.schema.syntaxes import DirectoryString, \
  IA5String,PropertiesSelectList,ISO8601Date,syntax_registry

# try to import vatnumber module
try:
  import stdnum, vatnumber
except ImportError:
  vatnumber = None


class Gender(PropertiesSelectList):
  oid = 'Gender-oid'
  desc = 'Representation of human sex (see ISO 5218)'
  properties_pathname = os.path.join(
    web2ldapcnf.etc_dir,'web2ldap','properties','attribute_select_gender.properties'
  )

syntax_registry.registerAttrType(
  Gender.oid,[
    '1.3.6.1.4.1.5427.1.389.4.7', # gender (defined for msPerson)
  ]
)


class DateOfBirth(ISO8601Date):
  oid = 'DateOfBirth-oid'
  desc = 'Date of birth: syntax YYYY-MM-DD, see ISO 8601'

  def _age(self,birth_dt):
    birth_date = datetime.date(year=birth_dt.year,month=birth_dt.month,day=birth_dt.day)
    current_date = datetime.date.today()
    age = current_date.year - birth_date.year
    if birth_date.month>current_date.month or \
       (birth_date.month==current_date.month and birth_date.day>current_date.day):
      age = age-1
    return age

  def _validate(self,attrValue):
    try:
      birth_dt = datetime.datetime.strptime(attrValue,self.storageFormat)
    except ValueError:
      return 0
    else:
      return self._age(birth_dt)>=0

  def displayValue(self,valueindex=0,commandbutton=0):
    raw_date = ISO8601Date.displayValue(self,valueindex,commandbutton)
    try:
      birth_dt = datetime.datetime.strptime(self.attrValue,self.storageFormat)
    except ValueError:
      return raw_date
    else:
      return '%s (%s years old)' % (raw_date,self._age(birth_dt))

syntax_registry.registerAttrType(
  DateOfBirth.oid,[
    '1.3.6.1.4.1.5427.1.389.4.2', # dateOfBirth
  ]
)


class LabeledBICandIBAN(DirectoryString):
  """
  More information:
  https://de.wikipedia.org/wiki/International_Bank_Account_Number
  http://www.pruefziffernberechnung.de/I/IBAN.shtml
  """
  oid = 'LabeledBICandIBAN-oid'
  desc = 'International bank account number (IBAN) syntax (see ISO 13616:1997)'

syntax_registry.registerAttrType(
  LabeledBICandIBAN.oid,[
    '1.3.6.1.4.1.5427.1.389.4.13', # labeledBICandIBAN
  ]
)


class EuVATId(IA5String):
  """
  More information:
  http://www.bzst.de/DE/Steuern_International/USt_Identifikationsnummer/Merkblaetter/Aufbau_USt_IdNr.pdf
  https://de.wikipedia.org/wiki/Umsatzsteuer-Identifikationsnummer
  """
  oid = 'EuVATId-oid'
  desc = 'Value Added Tax Ident Number of organizations within European Union'
  reObj=re.compile(
    r'^((AT)?U[0-9]{8}|' +
    r'(BE)?[0-9]{10}|' +
    r'(BG)?[0-9]{9,10}|' +
    r'(CY)?[0-9]{8}L|' +
    r'(CZ)?[0-9]{8,10}|' +
    r'(DE)?[0-9]{9}|' +
    r'(DK)?[0-9]{8}|' +
    r'(EE)?[0-9]{9}|' +
    r'(EL|GR)?[0-9]{9}|' +
    r'(ES)?[0-9A-Z][0-9]{7}[0-9A-Z]|' +
    r'(FI)?[0-9]{8}|' +
    r'(FR)?[0-9A-Z]{2}[0-9]{9}|' +
    r'(GB)?([0-9]{9}([0-9]{3})?|[A-Z]{2}[0-9]{3})|' +
    r'(HU)?[0-9]{8}|' +
    r'(IE)?[0-9]S[0-9]{5}L|' +
    r'(IT)?[0-9]{11}|' +
    r'(LT)?([0-9]{9}|[0-9]{12})|' +
    r'(LU)?[0-9]{8}|' +
    r'(LV)?[0-9]{11}|' +
    r'(MT)?[0-9]{8}|' +
    r'(NL)?[0-9]{9}B[0-9]{2}|' +
    r'(PL)?[0-9]{10}|' +
    r'(PT)?[0-9]{9}|' +
    r'(RO)?[0-9]{2,10}|' +
    r'(SE)?[0-9]{12}|' +
    r'(SI)?[0-9]{8}|' +
    r'(SK)?[0-9]{10})$'
  )

  def _validate(self,attrValue):
    if vatnumber:
      return vatnumber.check_vat(attrValue)
    else:
      return IA5String._validate(self,attrValue)

  def sanitizeInput(self,attrValue):
    return attrValue.upper().replace(' ','')

syntax_registry.registerAttrType(
  EuVATId.oid,[
    '1.3.6.1.4.1.5427.1.389.4.11', # euVATId
  ]
)


# Register all syntax classes in this module
for name in dir():
  syntax_registry.registerSyntaxClass(eval(name))

