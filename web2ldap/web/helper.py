# -*- coding: utf-8 -*-
"""
web2ldap.web.helper - Misc. stuff useful in CGI-BINs

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import os
import UserDict


REMOTE_ADDR_ENV_VARS = (
    'FORWARDED_FOR',
    'HTTP_X_FORWARDED_FOR',
    'HTTP_X_REAL_IP',
    'REMOTE_ADDR',
    'REMOTE_HOST'
)


def get_remote_ip(env):
    for var in REMOTE_ADDR_ENV_VARS:
        if var in env and env[var]:
            res = env[var]
            break
    else:
        res = None
    return res


class AcceptHeaderDict(UserDict.UserDict):
    """
    This dictionary class is used to parse
    Accept-header lines with quality weights.

    It's a base class for all Accept-* headers described
    in sections 14.1 to 14.5 of RFC2616.
    """

    def __init__(self, envKey, env=None, defaultValue=None):
        """
        Parse the Accept-* header line.

        httpHeader
            string with value of Accept-* header line
        """
        env = env or os.environ
        UserDict.UserDict.__init__(self)
        self.defaultValue = defaultValue
        self.preferred_value = []
        try:
            http_accept_value = [
                s
                for s in env[envKey].strip().split(',')
                if len(s)
            ]
        except KeyError:
            self.data = {'*':1.0}
        else:
            if not http_accept_value:
                self.data = {'*':1.0}
            else:
                self.data = {}
                for i in http_accept_value:
                    try:
                        c, w = i.split(';')
                    except ValueError:
                        c, w = i, ''
                    # Normalize charset name
                    c = c.strip().lower()
                    try:
                        _, qvalue_str = w.split('=', 1)
                        qvalue = float(qvalue_str)
                    except ValueError:
                        qvalue = 1.0
                    # Add to capability dictionary
                    if c:
                        self.data[c] = qvalue
        return # AcceptHeaderDict.__init__()

    def __getitem__(self, value):
        """
        value
            String representing the value for which to return
            the floating point capability weight.
        """
        return self.data.get(value.lower(), self.data.get('*', 0))

    def items(self):
        """
        Return the accepted values as tuples (value,weight)
        in descending order of capability weight
        """
        vals = self.data.items()
        vals.sort(lambda x, y: cmp(y[1], x[1]))
        return vals

    def keys(self):
        """
        Return the accepted values in descending order of capability weight
        """
        return [key for key, _ in self.items()]


class AcceptCharsetDict(AcceptHeaderDict):
    """
    Special class for Accept-Charset header
    """

    def __init__(self, envKey='HTTP_ACCEPT_CHARSET', env=None, defaultValue='utf-8'):
        AcceptHeaderDict.__init__(self, envKey, env, defaultValue)
        # Special treating of ISO-8859-1 charset to be compliant to RFC2616
        self.data['iso-8859-1'] = self.data.get('iso-8859-1', self.data.get('*', 1.0))
        return # AcceptCharsetDict.__init__()

    def preferred(self):
        """
        Return the value name with highest capability weight
        """
        lst = self.items()
        while lst and lst[0][0] != '*':
            try:
                u''.encode(lst[0][0])
            except LookupError:
                lst.pop(0)
            else:
                break
        if lst:
            if self.defaultValue and lst[0][0] == '*':
                return self.defaultValue
            return lst[0][0]
        return self.defaultValue
