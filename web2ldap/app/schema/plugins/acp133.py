# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for ACP-133
(see draft-dally-acp133-and-ldap)

Currently untested!
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import SelectList,DynamicDNSelectList,syntax_registry

#---------------------------------------------------------------------------
# Attribute types (see chapter 3 of draft-dally-acp133-and-ldap-01)
#---------------------------------------------------------------------------


class AddressListDN(DynamicDNSelectList):
  oid = 'AddressListDN-oid'
  desc = 'DN which points to address list entry '
  ldap_url = 'ldap:///_?cn?sub?(objectClass=addressList)'

syntax_registry.registerAttrType(
  AddressListDN.oid,[
    '2.16.840.1.101.2.2.1.61', # listPointer (see section 3.58 of draft-dally-acp133-and-ldap-01)
    '2.6.5.2.14',              # mhs-dl-related-lists (see section 3.70 of draft-dally-acp133-and-ldap-01)
  ]
)


class LMF(SelectList):
  oid = 'LMF-oid'
  desc = 'Language and Media Format (see section 3.59 of draft-dally-acp133-and-ldap-01)'
  attr_value_dict = {
    u'T':u'tape',
    u'A':u'ASCII',
    u'C':u'card',
  }

syntax_registry.registerAttrType(
  LMF.oid,[
    '2.16.840.1.101.2.2.1.62', # lmf
  ]
)


class TRC(SelectList):
  oid = 'TRC-oid'
  desc = 'Transmission Release Code (see section 3.126 of draft-dally-acp133-and-ldap-01)'
  attr_value_dict = {
    u'A':u'Australia',
    u'B':u'British Commonwealth less Canada, Australia, and New Zealand',
    u'C':u'Canada',
    u'U':u'US',
    u'X':u'Belgium, Denmark, France, Germany, Greece, Italy, Netherlands, Norway, Portugal, Turkey, NATO',
    u'Z':u'New Zealand',
  }

syntax_registry.registerAttrType(
  TRC.oid,[
    '2.16.840.1.101.2.2.1.97', # tRC
  ]
)


#---------------------------------------------------------------------------
# LDAP syntaxes (see chapter 6 of draft-dally-acp133-and-ldap-01)
#---------------------------------------------------------------------------

class ACPLegacyFormat(SelectList):
  oid = '2.16.840.1.101.2.2.2.17'
  desc = 'aCPLegacyFormat syntax (see section 6.1 of draft-dally-acp133-and-ldap-01)'
  attr_value_dict = {
    u'0':u'JANAP128',
    u'1':u'ACP126',
    u'2':u'DOI103',
    u'3':u'DOI103Special',
    u'4':u'ACP127',
    u'5':u'ACP127Converted',
    u'6':u'Reserved1',
    u'7':u'ACP127State',
    u'8':u'ACP127Modified',
    u'9':u'SOCOMMSpecial',
    u'10':u'SOCOMMNarrative',
    u'11':u'Reserved2',
    u'12':u'SOCOMMNarrativeSpecial',
    u'13':u'SOCOMMData',
    u'14':u'SOCOMMInternal',
    u'15':u'SOCOMMExternal',
    u'32':u'32 (national or bilateral use)',
    u'33':u'33 (national or bilateral use)',
    u'34':u'34 (national or bilateral use)',
    u'35':u'35 (national or bilateral use)',
    u'36':u'36 (national or bilateral use)',
    u'37':u'37 (national or bilateral use)',
    u'38':u'38 (national or bilateral use)',
    u'39':u'39 (national or bilateral use)',
    u'40':u'40 (national or bilateral use)',
    u'41':u'41 (national or bilateral use)',
    u'42':u'42 (national or bilateral use)',
    u'43':u'43 (national or bilateral use)',
    u'44':u'44 (national or bilateral use)',
    u'45':u'45 (national or bilateral use)',
    u'46':u'46 (national or bilateral use)',
    u'47':u'47 (national or bilateral use)',
    u'48':u'48 (national or bilateral use)',
  }


class ACPPreferredDelivery(SelectList):
  oid = '2.16.840.1.101.2.2.2.6'
  desc = 'aCPPreferredDelivery syntax (see section 6.2 of draft-dally-acp133-and-ldap-01)'
  attr_value_dict = {
    u'0':u'SMTP',
    u'1':u'ACP 127',
    u'2':u'MHS',
  }


class AddressListType(SelectList):
  oid = '2.16.840.1.101.2.2.2.8'
  desc = 'addressListType syntax (see section 6.6 of draft-dally-acp133-and-ldap-01)'
  attr_value_dict = {
    u'0':u'AIG',
    u'1':u'TYPE',
    u'2':u'CAD',
    u'3':u'TASKFORCE',
  }


class Classification(SelectList):
  oid = '2.16.840.1.101.2.2.2.4'
  desc = 'Classification syntax (see section 6.8 of draft-dally-acp133-and-ldap-01)'
  attr_value_dict = {
    u'0':u'unmarked',
    u'1':u'unclassified',
    u'2':u'restricted',
    u'3':u'confidential',
    u'4':u'secret',
    u'5':u'top secret',
  }


class Community(SelectList):
  oid = '2.16.840.1.101.2.2.2.5'
  desc = 'Community syntax (see section 6.9 of draft-dally-acp133-and-ldap-01)'
  attr_value_dict = {
    u'0':u'GENSER',
    u'1':u'SI',
    u'2':u'both',
  }


# Register all syntax classes in this module
for symbol_name in dir():
  syntax_registry.registerSyntaxClass(eval(symbol_name))
