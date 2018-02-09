# -*- coding: utf-8 -*-
"""
utctime.py - various functions for parsing display UTCTime
(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import time,datetime


class utcdatetime(datetime.datetime):
  pass


UTC_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


def strptime(s):
  # Extract and validate time zone information
  if len(s)==15 and s.endswith('Z'):
    # UTC Time (Zulu Time)
    dt = utcdatetime.strptime(s,r'%Y%m%d%H%M%SZ')
    return dt
  else:
    if len(s)>15 and s.endswith('Z'):
      # UTC Time (Zulu Time)
      s = s[:-1]
      tz_offset = datetime.timedelta(0)
    elif len(s)>=19 and s[-5] in ('+','-'):
      # Found + or - as time zone separator
      tzstr = s[-4:]
      if len(tzstr)!=4:
        raise ValueError
      tz_offset = datetime.timedelta(hours=int(tzstr[0:2]),minutes=int(tzstr[2:4]))
      s = s[:-5]
    else:
      # time zone part is missing
      raise ValueError
    s = s.replace(',','.')
    # Extract and validate date and time information
    if '.' in s:
      # There seems to be a fraction part
      dt = utcdatetime.strptime(s,r'%Y%m%d%H%M%S.%f')
    else:
      # no fraction part
      dt = utcdatetime.strptime(s,r'%Y%m%d%H%M%S')
    return dt - tz_offset


def strftimeiso8601(t):
  """
  Return a UTC datetime string.
  """
  try:
    return t.strftime(UTC_TIME_FORMAT)
  except AttributeError:
   return time.strftime(UTC_TIME_FORMAT,t)
