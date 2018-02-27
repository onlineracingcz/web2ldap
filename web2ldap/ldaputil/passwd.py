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

import base64
import hashlib

from ldap0.pw import random_string, PWD_OCTETS_ALPHABET, PWD_UNIX_CRYPT_ALPHABET

AVAIL_USERPASSWORD_SCHEMES = {
  'sha':'SHA-1',
  'ssha':'salted SHA-1',
  'md5':'MD5',
  'smd5':'salted MD5',
  'sha256':'SHA-256',
  'ssha256':'salted SHA-256',
  'sha384':'SHA-384',
  'ssha384':'salted SHA-384',
  'sha512':'SHA-512',
  'ssha512':'salted SHA-512',
  '':'plain text',
}

try:
  import crypt
except ImportError:
  pass
else:
  AVAIL_USERPASSWORD_SCHEMES['crypt'] = 'Unix crypt(3)'

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


def user_password_hash(password,scheme,salt=None):
    """
    Return hashed password (including salt).
    """
    scheme = scheme.lower().strip()
    if not scheme:
        return password
    if not scheme in AVAIL_USERPASSWORD_SCHEMES.keys():
        raise ValueError,'Hashing scheme %r not supported.' % (scheme)
    if salt is None:
        if scheme=='crypt':
            salt = random_string(PWD_UNIX_CRYPT_ALPHABET,2)
        elif scheme in ('smd5','ssha','ssha256','ssha384','ssha512'):
            salt = random_string(PWD_OCTETS_ALPHABET,12)
        else:
            salt = ''
    if scheme=='crypt':
        encoded_pw = crypt.crypt(password,salt)
    elif SCHEME2HASHLIBFUNC.has_key(scheme):
        encoded_pw = base64.encodestring(SCHEME2HASHLIBFUNC[scheme](password+salt).digest()+salt).strip().replace('\n','')
    else:
        encoded_pw = password
    return '{%s}%s' % (scheme.upper(),encoded_pw)
