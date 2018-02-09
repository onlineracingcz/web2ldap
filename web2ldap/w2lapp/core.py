# -*- coding: utf-8 -*-
"""
w2lapp.core: some core functions used throughout web2ldap

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import os,time,ldap0,w2lapp.cnf,w2lapp

from types import StringType,UnicodeType

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

# Switch off processing .ldaprc or ldap.conf
os.environ['LDAPNOINIT']='1'

ldap0._trace_level=w2lapp.cnf.misc.ldap_trace_level
ldap0.set_option(ldap0.OPT_DEBUG_LEVEL,w2lapp.cnf.misc.ldap_opt_debug_level)
ldap0.set_option(ldap0.OPT_RESTART,0)
ldap0.set_option(ldap0.OPT_DEREF,0)
ldap0.set_option(ldap0.OPT_REFERRALS,0)

startUpTime = time.time()

# Set up configuration for restricting access to the preconfigured LDAP URI list
ldap_uri_list_check_dict = w2lapp.cnf.PopulateCheckDict(w2lapp.cnf.hosts.ldap_uri_list)
