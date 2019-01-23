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
    if isinstance(data, long):
        # long integer
        L = []
        while data:
            L.append(chr(data & 0xFFL))
            data = data >> 8
        L.reverse()
        d = ''.join(L)
    elif isinstance(data, bytes):
        # string buffer
        d = data
    else:
        raise TypeError('Parameter data can only be a bytes or long integer.')
    if wrap:
        bytesperline = wrap-indent / 3
    else:
        bytesperline = len(data)
    convert = lambda x, d=delimiter: '%02X%s' % (ord(x), d)
    s = [' '*indent+''.join(map(convert, d[0:bytesperline]))]
    i = bytesperline
    while i <= len(d):
        s.append(' '*indent+''.join(map(convert, d[i:i+bytesperline])))
        i = i + bytesperline
    return linesep.join(s)


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
