"""
utctime.py - various functions for parsing display UTCTime

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time, calendar

class UTCTime:
  """
  UTCTime object

  The timestamp is stored internally as time tuple in self.__datetime__.
  """

  def __init__(self,datetime):
    """
    Intialize a UTCTime object
    
    Parameter datetime can be either of type
    string        UTCTime string like 20000914101638Z
    tuple        time tuple like used in module time
    integer        Seconds since "epoch".
    """
    self.__datetime__ = self.__timetuple__(datetime)

  def __timetuple__(self,datetime):
    """Convert datetime type to time tuple"""
    if type(datetime)==type(''):
      # string representation
      return self.__strptime__(datetime)
    elif type(datetime)==type(()) and len(datetime)==9:
      # time tuple like used in module time
      return datetime
    elif type(datetime)==type(1.0):
      # seconds as floating point
      return time.gmtime(datetime)
    else:
      raise TypeError, "Parameter datetime must be of type string, time tuple or float seconds."

  def __nonzero__(self):
    return self.__datetime__!=None

  def __cmp__(self,other):
    if other==None:
      return 0
    elif isinstance(other,UTCTime):
      return cmp(self.__datetime__,other.__datetime__)
    else:
      return cmp(self.__datetime__,self.__timetuple__(other))

  def __str__(self):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ',self.__datetime__)

  def __repr__(self):
    return time.strftime('%Y%m%d%H%M%SZ',self.__datetime__)

  def __strptime__(self,s):
    """
    Parse a UTC time string.
    """
    if type(s)!=type(''):
      raise TypeError, "Parameter s must be of string type."
    if s[-1].upper()!='Z':
      raise ValueError, "Trailing Z of UTC time string is missing."
    if len(s)==15:
      # YYYYmmddHHMMSS
      year,month,day,hour,minute,second = long(s[0:4]),long(s[4:6]),long(s[6:8]),long(s[8:10]),long(s[10:12]),long(s[12:14])
    else:
      if len(s)==13:
        # YYmmddHHMMSS
        year,month,day,hour,minute,second = long(s[0:2]),long(s[2:4]),long(s[4:6]),long(s[6:8]),long(s[8:10]),long(s[10:12])
      elif len(s)==11:
        # YYmmddHHMM
        year,month,day,hour,minute,second = long(s[0:2]),long(s[2:4]),long(s[4:6]),long(s[6:8]),long(s[8:10]),0
      if year<=50:
        year=year+2000
      else:
        year=year+1900
    return time.gmtime(calendar.timegm((year,month,day,hour,minute,second,0,1,-1)))
