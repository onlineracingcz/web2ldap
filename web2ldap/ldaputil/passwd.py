# -*- coding: ascii -*-
"""
ldaputil.passwd - client-side password setting

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import base64
import hashlib
import crypt
import secrets

from ldap0.pw import random_string, PWD_UNIX_CRYPT_ALPHABET

AVAIL_USERPASSWORD_SCHEMES = {
    'crypt': 'Unix crypt(3)',
    'sha': 'SHA-1',
    'ssha': 'salted SHA-1',
    'md5': 'MD5',
    'smd5': 'salted MD5',
    'sha256': 'SHA-256',
    'ssha256': 'salted SHA-256',
    'sha384': 'SHA-384',
    'ssha384': 'salted SHA-384',
    'sha512': 'SHA-512',
    'ssha512': 'salted SHA-512',
    '': 'plain text',
}


SALTED_USERPASSWORD_SCHEMES = {
    'smd5',
    'ssha',
    'ssha256',
    'ssha384',
    'ssha512',
}


# map lower-cased password scheme to hash function
SCHEME2HASHLIBFUNC = {
    'sha': hashlib.sha1,
    'ssha': hashlib.sha1,
    'md5': hashlib.md5,
    'smd5': hashlib.md5,
    'sha256': hashlib.sha256,
    'ssha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'ssha384': hashlib.sha384,
    'sha512': hashlib.sha512,
    'ssha512': hashlib.sha512,
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
    if scheme == 'crypt':
        encoded_pw = crypt.crypt(
            password.decode('utf-8'),
            random_string(PWD_UNIX_CRYPT_ALPHABET.decode('ascii'), 2)
        ).encode('ascii')
    elif scheme in SCHEME2HASHLIBFUNC:
        salt = secrets.token_bytes(12)
        encoded_pw = base64.encodebytes(
            SCHEME2HASHLIBFUNC[scheme](password+salt).digest()+salt
        ).strip().replace(b'\n', b'')
    else:
        encoded_pw = password
    return b'{%s}%s' % (scheme.upper().encode('ascii'), encoded_pw)
