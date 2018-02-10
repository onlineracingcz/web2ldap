"""
x500.py - X.500 objects
(c) by Michael Stroeder <michael@stroeder.com>

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

# Additional encodings
import t61_8
# Pisces
from pisces import asn1
# mspki itself
import mspki.asn1helper

strtag2charset = {
  asn1.PRINTABLE_STRING:'ascii',
  asn1.T61STRING:'t61-8',
  asn1.IA5STRING:'ascii',
  asn1.UTF8STRING:'utf-8',
  asn1.BMPSTRING:'utf-16-be',
}

class AttributeTypeAndValue(asn1.Sequence):
  """
  Class for X.500 attributetype / value pairs

  AttributeTypeAndValue ::= SEQUENCE {
    type     AttributeType,
    value    AttributeValue }

  AttributeType ::= OBJECT IDENTIFIER

  AttributeValue ::= ANY DEFINED BY AttributeType
  """
  def __init__(self,val):
    asn1.Sequence.__init__(self,val)

  def __repr__(self):
    return '%s: %s' % (str(self.val[0]),str(self.val[1]))

  def html(self):
    return repr(self)

class RelativeDistinguishedName(asn1.Set):
  """
  Class for X.500 relative distinguished names

  RelativeDistinguishedName ::=
    SET OF AttributeTypeAndValue
  """

class Name(asn1.Sequence):
  """
  Class for X.500 distinguished names

  Name ::= CHOICE {
    RDNSequence }

  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
  """

  def __init__(self,val):
    self._name = []
    for i in val:
      try:
        attr_value = unicode(i[0].val[1].val,strtag2charset[i[0].val[1].tag])
      except UnicodeError:
        attr_value = unicode(repr(i[0].val[1].val)[1:-1],'ascii')
      self._name.append((i[0].val[0],attr_value))

  def descr(self,oids=None,charset='utf-8'):
    """Distinguished Name object with OIDs replaced by descriptions"""
    f=mspki.asn1helper.GetOIDDescription
    return [
      (f(i[0],oids),i[1])
      for i in self._name
    ]

  def htmldescr(self,oids=None,charset='utf-8'):
    """Distinguished Name object with OIDs replaced by descriptions"""
    f=mspki.asn1helper.GetOIDDescription
    return [
      ('%s (%s)' % (f(i[0],oids),i[0]),i[1])
      for i in self._name
    ]

  def __str__(self,oids=None,charset='utf-8'):
    """
    String representation of distinguished name for displaying
    
    This mimics the string output behaviour of OpenSSL.
    If parameter oids is set (dictionary returned by asn1.parseCfg()
    descriptions are used instead of OIDs.
    """
    oids = oids or mspki.asn1helper.oids
    if oids:
      rdnlist = self.descr(oids)
    else:
      rdnlist = self._name
    return ''.join([
      '/%s=%s' % (attr_type,attr_value.encode(charset))
      for attr_type,attr_value in rdnlist
    ])

  def __repr__(self,oids=None):
    """
    See RFC2253: String representation of X.500 DNs
    
    If parameter oids is set (dictionary returned by asn1.parseCfg()
    descriptions are used instead of OIDs.
    """
    oids = oids or mspki.asn1helper.oids
    if oids:
      rdnlist = self.descr(oids)
    else:
      rdnlist = self._name
    rdnlist.reverse()
    return ','.join([
      '%s=%s' % (attr_type,attr_value.encode('utf-8'))
      for attr_type,attr_value in rdnlist
    ])

  def html(self,oids=None,charset='utf-8'):
    """
    HTML-formatted string representation of distinguished name.
    
    If parameter oids is set (dictionary returned by asn1.parseCfg()
    descriptions are used instead of OIDs.
    """
    oids = oids or mspki.asn1helper.oids
    if oids:
      rdnlist = self.htmldescr(oids)
    else:
      rdnlist = self._name
    return '<table>\n%s\n</table>\n' % (
      '\n'.join([
        '</tr><th>%s</th><td>%s</td></tr>' % (attr_type,attr_value.encode(charset))
        for attr_type,attr_value in rdnlist
      ])
    )

