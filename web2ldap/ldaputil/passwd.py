# -*- coding: utf-8 -*-
"""
ldaputil.passwd - client-side password setting

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import base64
import hashlib
import crypt

from ldap0.pw import random_string, PWD_OCTETS_ALPHABET, PWD_UNIX_CRYPT_ALPHABET

AVAIL_USERPASSWORD_SCHEMES = {
    u'crypt': u'Unix crypt(3)',
    u'sha': u'SHA-1',
    u'ssha': u'salted SHA-1',
    u'md5': u'MD5',
    u'smd5': u'salted MD5',
    u'sha256': u'SHA-256',
    u'ssha256': u'salted SHA-256',
    u'sha384': u'SHA-384',
    u'ssha384': u'salted SHA-384',
    u'sha512': u'SHA-512',
    u'ssha512': u'salted SHA-512',
    u'': u'plain text',
}


SALTED_USERPASSWORD_SCHEMES = {
    u'smd5',
    u'ssha',
    u'ssha256',
    u'ssha384',
    u'ssha512',
}


# map lower-cased password scheme to hash function
SCHEME2HASHLIBFUNC = {
    u'sha': hashlib.sha1,
    u'ssha': hashlib.sha1,
    u'md5': hashlib.md5,
    u'smd5': hashlib.md5,
    u'sha256': hashlib.sha256,
    u'ssha256': hashlib.sha256,
    u'sha384': hashlib.sha384,
    u'ssha384': hashlib.sha384,
    u'sha512': hashlib.sha512,
    u'ssha512': hashlib.sha512,
}


def user_password_hash(password, scheme, salt=None):
    """
    Return hashed password (including salt).
    """
    scheme = scheme.lower().strip()
    if not scheme:
        return password
    if scheme not in AVAIL_USERPASSWORD_SCHEMES.keys():
        raise ValueError('Hashing scheme %r not supported.' % (scheme))
    if scheme == u'crypt':
        encoded_pw = crypt.crypt(
            password.decode('utf-8'),
            random_string(PWD_UNIX_CRYPT_ALPHABET.decode('ascii'), 2)
        ).encode('ascii')
    elif scheme in SCHEME2HASHLIBFUNC:
        salt = random_string(PWD_OCTETS_ALPHABET, 12)
        encoded_pw = base64.encodestring(
            SCHEME2HASHLIBFUNC[scheme](password+salt).digest()+salt
        ).strip().replace(b'\n', b'')
    else:
        encoded_pw = password
    return b'{%s}%s' % (scheme.upper().encode('ascii'), encoded_pw)
