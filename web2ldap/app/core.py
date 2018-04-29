# -*- coding: utf-8 -*-
"""
web2ldap.app.core: some core functions used throughout web2ldap

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import
from types import StringType,UnicodeType

import os,time

# Switch off processing .ldaprc or ldap.conf
os.environ['LDAPNOINIT']='1'

import ldap0

import web2ldapcnf,web2ldapcnf.hosts

import web2ldap.app.cnf


def str2unicode(s,charset):
  if type(s) is StringType:
    try:
      return unicode(s,charset)
    except UnicodeError:
      return unicode(s,'iso-8859-1')
  else:
    return s


class ErrorExit(Exception):
  """Base class for web2ldap application exceptions"""

  def __init__(self,Msg):
    assert type(Msg)==UnicodeType, TypeError("Type of argument 'Msg' must be UnicodeType: %s" % repr(Msg))
    self.Msg = Msg


########################################################################
# Initialize some constants
########################################################################

# Raise UnicodeError instead of output of UnicodeWarning
from exceptions import UnicodeWarning
from warnings import filterwarnings
filterwarnings(action="error", category=UnicodeWarning)

ldap0._trace_level=web2ldapcnf.ldap_trace_level
ldap0.set_option(ldap0.OPT_DEBUG_LEVEL,web2ldapcnf.ldap_opt_debug_level)
ldap0.set_option(ldap0.OPT_RESTART,0)
ldap0.set_option(ldap0.OPT_DEREF,0)
ldap0.set_option(ldap0.OPT_REFERRALS,0)

startUpTime = time.time()

# Set up configuration for restricting access to the preconfigured LDAP URI list
ldap_uri_list_check_dict = web2ldap.app.cnf.PopulateCheckDict(web2ldapcnf.hosts.ldap_uri_list)
