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

import struct


def HexString(data, delimiter=':', wrap=None, indent=0, linesep='\n'):
    """
    Return a string representation of a fingerprint.

    The bytes are printed in hex separated by the character
    defined in delimiter.
    """
    assert isinstance(data, bytes), TypeError('Expected data to be bytes, got %r' % (data))
    if wrap:
        bytesperline = wrap - indent / 3
    else:
        bytesperline = len(data)
    convert = lambda x, d=delimiter: '%02X%s' % (ord(x), d)
    s = [' '*indent+''.join(map(convert, data[0:bytesperline]))]
    i = bytesperline
    while i <= len(data):
        s.append(' '*indent+''.join(map(convert, data[i:i+bytesperline])))
        i += bytesperline
    return linesep.join(s)


def bytestolong(s):
    """
    Convert a byte string to a long integer.
    """
    acc = 0
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = '\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc
