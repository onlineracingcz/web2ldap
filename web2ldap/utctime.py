# -*- coding: utf-8 -*-
"""
web2ldap.utctime - various functions for parsing display UTCTime

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time
import datetime


UTC_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def strptime(s):
    # Extract and validate time zone information
    len_dt_str = len(s)
    if s[-1].upper() == 'Z':
        # assume UTC Time string
        if len_dt_str == 15:
            # with century in the year
            dt = datetime.datetime.strptime(s, r'%Y%m%d%H%M%SZ')
            return dt
        if len_dt_str == 13:
            # without century in the year
            dt = datetime.datetime.strptime(s, r'%y%m%d%H%M%SZ')
            return dt
        elif len_dt_str > 16:
            # probably fractions in seconds part
            s = s[:-1]
            tz_offset = datetime.timedelta(0)
        else:
            raise ValueError('Could not determine UTC time format of %r' % (s))
    elif len_dt_str >= 19 and s[-5] in {'+', '-'}:
        # Found + or - as time zone separator
        tzstr = s[-4:]
        tz_offset = datetime.timedelta(
            hours=int(tzstr[0:2]),
            minutes=int(tzstr[2:4]),
        )
        s = s[:-5]
    else:
        raise ValueError('Time zone part missing in %r' % (s))
    s = s.replace(',', '.')
    # Extract and validate date and time information
    if '.' in s:
        # There seems to be a fraction part
        dt = datetime.datetime.strptime(s, r'%Y%m%d%H%M%S.%f')
    else:
        # no fraction part
        dt = datetime.datetime.strptime(s, r'%Y%m%d%H%M%S')
    return dt - tz_offset


def strftimeiso8601(t):
    """
    Return a UTC datetime string.
    """
    try:
        return t.strftime(UTC_TIME_FORMAT)
    except AttributeError:
        return time.strftime(UTC_TIME_FORMAT, t)
