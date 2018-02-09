# -*- coding: utf-8 -*-
"""
ldaputil.controls - basic LDAP functions
(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import ldap0.controls.readentry
from ldap0.controls.simple import ValueLessRequestControl,ResponseControl

from pyasn1_modules.rfc2251 import LDAPDN,PartialAttributeList,SearchResultEntry
from pyasn1.type import namedtype,univ
from pyasn1.codec.ber import decoder
from pyasn1.error import PyAsn1Error


class ReadEntryControl(ldap0.controls.readentry.ReadEntryControl):

  class OpenLDAPITS6899SearchResultEntry(univ.Sequence):
    """
    This is an ASN.1 description of SearchResultEntry not compliant to LDAPv3
    which implements a work-around for OpenLDAP's ITS#6899
    """
    tagSet = univ.Sequence.tagSet # work-around: instead of implicit tagging
    componentType = namedtype.NamedTypes(
      namedtype.NamedType('objectName', LDAPDN()),
      namedtype.NamedType('attributes', PartialAttributeList())
    )

  def decodeControlValue(self,encodedControlValue):
    try:
      decodedEntry,_ = decoder.decode(encodedControlValue,asn1Spec=SearchResultEntry())
    except PyAsn1Error:
      decodedEntry,_ = decoder.decode(encodedControlValue,asn1Spec=self.OpenLDAPITS6899SearchResultEntry())
    self.dn = str(decodedEntry[0])
    self.entry = {}
    for attr in decodedEntry[1]:
      self.entry[str(attr[0])] = [ str(attr_value) for attr_value in attr[1] ]


class PreReadControl(ReadEntryControl):
  controlType = ldap0.CONTROL_PRE_READ

# override ldap0's default implementation
ldap0.controls.KNOWN_RESPONSE_CONTROLS.reg(PreReadControl)


class PostReadControl(ReadEntryControl):
  controlType = ldap0.CONTROL_POST_READ

# override ldap0's default implementation
ldap0.controls.KNOWN_RESPONSE_CONTROLS.reg(PostReadControl)
