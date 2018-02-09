"""
nsext.py - classes for X.509v3 extensions specified by Netscape
(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)

Unlike other extension classes where the ASN.1 type names are used
as class names we use the OpenSSL names as class names.

netscape-cert-extension OBJECT IDENTIFIER :: = { netscape 1 } 
"""

# Pisces
from pisces import asn1
# mspki itself
import asn1types


# List of string representations of extension OIDs defined by Netscape
netscape_extension_oidlist = [
  '2.16.840.1.113730.1.7',
  '2.16.840.1.113730.1.2',
  '2.16.840.1.113730.1.4',
  '2.16.840.1.113730.1.3',
  '2.16.840.1.113730.1.1',
  '2.16.840.1.113730.1.8',
  '2.16.840.1.113730.1.13'
]


class NsString(asn1.IA5String):
  """
  Base class for extensions defined by Netscape containing solely a string.
  """
  def __init__(self,val):
    self.val = val

  def __str__(self):
    return str(self.val)


class NsUrl(NsString):
  """
  Base class for URL extensions defined by Netscape
  """
  def html(self,nsBaseUrl='',serial=None,target=''):
    if target:
      target = 'target="%s"' % (target)
    if str(self.val)[-1]!='?' or serial is None:
      serial = ''
    return '<a target="%s" href="%s%s%s%s" %s>%s</a>' % (
      asn1types.url_target,
      asn1types.url_prefix,
      nsBaseUrl,
      self,serial,
      target,self
    )


class NsCertType(asn1types.BitString):
  """
  netscape-cert-type OBJECT IDENTIFIER ::= {
  netscape-cert-extension 1 } 

  bit-0 SSL client - this cert is certified for SSL client authentication use
  bit-1 SSL server - this cert is certified for SSL server authentication use
  bit-2 S/MIME - this cert is certified for use by clients(New in PR3)
  bit-3 Object Signing - this cert is certified for signing objects such as Java applets and plugins(New in PR3)
  bit-4 Reserved - this bit is reserved for future use
  bit-5 SSL CA - this cert is certified for issuing certs for SSL use
  bit-6 S/MIME CA - this cert is certified for issuing certs for S/MIME use(New in PR3)
  bit-7 Object Signing CA - this cert is certified for issuing certs for Object Signing(New in PR3)
  """
  bit_str = {
    0:'SSL client',1:'SSL server',2:'S/MIME',3:'Object Signing',
    4:'Reserved',5:'SSL CA',6:'S/MIME CA',7:'Object Signing CA'
  }

  def __str__(self):
    return asn1types.BitString.__str__(self)


class NsComment(NsString):
  """
  netscape-comment OBJECT IDENTIFIER ::= { netscape-cert-extension 13 }
  """


class NsBaseUrl(NsString):
  """
  netscape-base-url OBJECT IDENTIFIER ::= { netscape-cert-extension 2 }
  """


class NsCaRevocationUrl(NsUrl):
  """
  netscape-ca-revocation-url OBJECT IDENTIFIER ::= { netscape-cert-extension 4 }
  """


class NsRevocationUrl(NsUrl):
  """
  netscape-revocation-url OBJECT IDENTIFIER ::= { netscape-cert-extension 3 }
  """


class NsRenewalUrl(NsUrl):
  """
  netscape-cert-renewal-url OBJECT IDENTIFIER ::= { netscape-cert-extension 7 }
  """


class NsCaPolicyUrl(NsUrl):
  """
  netscape-ca-policy-url OBJECT IDENTIFIER ::= { netscape-cert-extension 8 }
  """


class NsSslServerName(NsString):
  """
  netscape-ssl-server-name OBJECT IDENTIFIER ::= { netscape-cert-extension 12 }
  """

