"""
vendorext.py - classes for vendor specific X.509v3 extensions
(c) by Michael Stroeder <michael@stroeder.com>

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

# Pisces
from web2ldap.pisces import asn1


class EntrustVersInfo(asn1.OctetString):
  """
  entrustVersInfo EXTENSION ::= {
          SYNTAX EntrustVersInfoSyntax
          IDENTIFIED BY { id-nsn-ext 0}
  }

  EntrustVersInfoSyntax ::= OCTET STRING
  """
  def __init__(self,val):
    asn1.OctetString.__init__(self,val)
    self.val = val

  def __str__(self):
    return str(self.val[0])+repr(self.val[1])


VERISIGN_CZAG_KEY='\x86\xa1\x00\x00\x00\xfb\x0b\xf2\xc8\xb2&\x9d[\xc1\xe7\x00y\xae\x93\x8br\xcd\x00\xa7\x00'

class VerisignCZAG(asn1.IA5String):
  """
  See http://www.renfro.org/scott/writing/verisign-demographics.pdf
  """
  def __init__(self,val):
    asn1.IA5String.__init__(self,val)
    v = val.val
    c =''.join([
      chr(int(v[i:i+2],16))
      for i in range(66,len(v)-2,2)
    ])
    k = VERISIGN_CZAG_KEY
    assert len(c)==len(k),'Length of c (%d) and k (%d) differ' % (len(c),len(k))
    p = ''.join([
      chr(ord(k[i])^ord(c[i]))
      for i in range(len(c))
    ])
    self.country = p[0:2]
    self.zipCode = p[5:15].strip()
    self.age     = '19'+p[20:22]+'-'+p[16:18]+'-'+p[18:20]
    self.gender  = p[23]

  def html(self):
    return """
    <dl>
      <dt>country</dt>
      <dd>%(country)s</dd>
      <dt>zipCode</dt>
      <dd>%(zipCode)s</dd>
      <dt>age</dt>
      <dd>%(age)s</dd>
      <dt>gender</dt>
      <dd>%(gender)s</dd>
    </dl>
    """ % self.__dict__

if __name__ == '__main__':
  print VerisignCZAG(
    asn1.IA5String(
      'd4652bd63f2047029298763c9d2f275069c7359bed1b059da75bc4bc9701747da5d3f2141beadb2bd2e89215ae6bf0d311499da1b845fef3ea450c'
    )
  ).html()
