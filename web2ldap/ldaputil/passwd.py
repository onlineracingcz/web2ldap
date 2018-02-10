# -*- coding: utf-8 -*-
"""
ldaputil.passwd - client-side password setting
(c) by Michael Stroeder <michael@stroeder.com>

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import random
import base64
import hashlib


# Alphabet for encrypted passwords (see module crypt)
CRYPT_ALPHABET = './0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

# Try to determine the hash types available on the current system by
# checking all required modules are in place.
# After all AVAIL_USERPASSWORD_SCHEMES is a list of tuples containing
# [(hash-id,(hash-description)].
AVAIL_USERPASSWORD_SCHEMES = {
  'sha':'userPassword SHA-1',
  'ssha':'userPassword salted SHA-1',
  'md5':'userPassword MD5',
  'smd5':'userPassword salted MD5',
  'sha256':'userPassword SHA-256',
  'ssha256':'userPassword salted SHA-256',
  'sha384':'userPassword SHA-384',
  'ssha384':'userPassword salted SHA-384',
  'sha512':'userPassword SHA-512',
  'ssha512':'userPassword salted SHA-512',
  '':'userPassword plain text',
}

try:
  import crypt
except ImportError:
  pass
else:
  AVAIL_USERPASSWORD_SCHEMES['crypt'] = 'userPassword Unix crypt'

AVAIL_AUTHPASSWORD_SCHEMES = {
  'sha1':'authPassword SHA-1',
  'md5':'authPassword MD5',
}


SCHEME2HASHLIBFUNC = {
  'sha':hashlib.sha1,
  'ssha':hashlib.sha1,
  'md5':hashlib.md5,
  'smd5':hashlib.md5,
  'sha256':hashlib.sha256,
  'ssha256':hashlib.sha256,
  'sha384':hashlib.sha384,
  'ssha384':hashlib.sha384,
  'sha512':hashlib.sha512,
  'ssha512':hashlib.sha512,
}

_UnicodeType = type(u'')


DEFAULT_SALT_ALPHABET = tuple([
  chr(i)
  for i in range(0,256)
])


def RandomString(length,chars):
  """
  Create a random byte string.

  length
      Requested length of string.
  chars
      If non-zero string it is assumed to contain all valid chars for the
      random string. If zero-length or None the result returned is an
      arbitrary octet string.
  """
  sys_rand = random.SystemRandom()
  chars_bounce = len(chars)-1
  return ''.join([
    chars[sys_rand.randint(0,chars_bounce)]
    for _ in range(length)
  ])


class Password:
  """
  Base class for plain-text LDAP passwords.
  """

  def __init__(self,l,dn=None,charset='utf-8'):
    """
    l
        LDAPObject instance to operate with. The application
        is responsible to bind with appropriate bind DN before(!)
        creating the Password instance.
    dn
        string object with DN of entry
    charset
        Character set for encoding passwords. Note that this might
        differ from the character set used for the normal directory strings.
    """
    self._l = l
    self._dn = dn
    self._charset = charset

  def encodePassword(self,plainPassword,scheme=None):
    """
    encode plainPassword into plain text password
    """
    if type(plainPassword)==_UnicodeType:
      plainPassword = plainPassword.encode(self._charset)
    return plainPassword


class UserPassword(Password):
  """
  Class for LDAP password changing in userPassword attribute

  RFC 2307:
    http://www.ietf.org/rfc/rfc2307.txt
  OpenLDAP FAQ:
    https://www.openldap.org/faq/data/cache/419.html
  Netscape Developer Docs:
    http://developer.netscape.com/docs/technote/ldap/pass_sha.html
  """
  passwordAttributeType='userPassword'
  _hash_bytelen = {'md5':16,'sha':20}

  def _hashPassword(self,password,scheme,salt=None):
    """
    Return hashed password (including salt).
    """
    scheme = scheme.lower()
    if not scheme in AVAIL_USERPASSWORD_SCHEMES.keys():
      raise ValueError,'Hashing scheme %s not supported for class %s.' % (
        scheme,self.__class__.__name__
      )
      raise ValueError,'Hashing scheme %s not supported.' % (scheme)
    if salt is None:
      if scheme=='crypt':
        salt = RandomString(2,CRYPT_ALPHABET)
      elif scheme in ('smd5','ssha','ssha256','ssha384','ssha512'):
        salt = RandomString(12,DEFAULT_SALT_ALPHABET)
      else:
        salt = ''
    if scheme=='crypt':
      return crypt.crypt(password,salt)
    elif SCHEME2HASHLIBFUNC.has_key(scheme):
      return base64.encodestring(SCHEME2HASHLIBFUNC[scheme](password+salt).digest()+salt).strip().replace('\n','')
    else:
      return password

  def encodePassword(self,plainPassword,scheme):
    """
    encode plainPassword according to RFC2307 password attribute syntax
    """
    plainPassword = Password.encodePassword(self,plainPassword)
    if scheme:
      return ('{%s}%s' % (
        scheme.upper(),
        self._hashPassword(plainPassword,scheme)
      )).encode('ascii')
    else:
      return plainPassword


class UnicodePwd(Password):
  """
  Class for LDAP password changing in unicodePwd attribute
  on Active Directory servers.
  (see https://msdn.microsoft.com/en-us/library/cc223248.aspx)
  """
  passwordAttributeType='unicodePwd'

  def __init__(self,l=None,dn=None):
    """
    Like CharsetPassword.__init__() with one additional parameter.
    """
    Password.__init__(self,l,dn)
    self._charset = 'utf-16-le'

  def encodePassword(self,plainPassword,scheme=None):
    """
    Enclose Unicode password string in double-quotes.
    """
    return Password.encodePassword(self,'"%s"' % (plainPassword))
