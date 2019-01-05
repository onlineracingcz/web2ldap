"""
util.py - handle certificate data with plain Python 1.5.2 lib

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import re,base64

pem_re = re.compile('-----BEGIN (CERTIFICATE|X509 CRL|CERTIFICATE REQUEST|PKCS7|CMS|PRIVATE KEY|ATTRIBUTE CERTIFICATE)-----([ \w+/=\r\n]+?)-----END (CERTIFICATE|X509 CRL|CERTIFICATE REQUEST|PKCS7)-----',re.S+re.M)
base64_re = re.compile('^[ \w+/=\r\n]+$',re.S+re.M)

def is_base64(s):
  """Regex based check if s has only chars used with base64 encoding"""
  rm = base64_re.match(s)
  return rm!=None

def HexString(data,delimiter=':',wrap=None,indent=0,linesep='\n'):
  """
  Return a string representation of a fingerprint.
  
  The bytes are printed in hex separated by the character
  defined in delimiter.
  """
  if type(data)==type(0L):
    # long integer
    L=[]
    while data:
      L.append(chr(data & 0xFFL))
      data = data >> 8
    L.reverse()
    d=''.join(L)
  elif type(data)==type(''):
    # string buffer
    d = data
  else:
    raise TypeError, "Parameter data can only be a string or long integer."
  if wrap:
    bytesperline = (wrap-indent) / 3
  else:
    bytesperline = len(data)
  convert = lambda x,d=delimiter:'%02X%s' % (ord(x),d)
  s = [' '*indent+''.join(map(convert,d[0:bytesperline]))]
  i = bytesperline
  while i<=len(d):
    s.append(' '*indent+''.join(map(convert,d[i:i+bytesperline])))
    i = i+bytesperline
  return linesep.join(s)

def extract_pem(cert_text):
  """
  Extract all base64 encoded certs in a text file to a list of strings
  """
  result = []
  for begin_type,cert_base64,end_type in pem_re.findall(cert_text):
    if begin_type!=end_type:
      raise ValueError,"-----BEGIN %s----- and -----END %s----- does not match" % (begin_type,end_type)
    result.append((begin_type,cert_base64.strip()))
  return result

def der2pem(cert_der,cert_type='CERTIFICATE'):
  """
  Convert single binary DER-encoded certificate to base64 encoded format
  """
  return """-----BEGIN %s-----
%s-----END %s-----
""" % (cert_type,base64.encodestring(cert_der),cert_type)

def pem2der(cert_text):
  """
  Convert single base64 encoded certificate to binary DER-encoded format
  """
  _,cert_base64  = extract_pem(cert_text)[0]
  return base64.decodestring(cert_base64.strip())


# longtobytes and bytestolong are stolen from
# amkCrypto.Util.numbers

import struct

def longtobytes(n, blocksize=0):
    """Convert a long integer to a byte string

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] <> '\000':
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * '\000' + s
    return s

def bytestolong(s):
    """Convert a byte string to a long integer.

    This is (essentially) the inverse of longtobytes().
    """
    acc = 0L
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = '\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

