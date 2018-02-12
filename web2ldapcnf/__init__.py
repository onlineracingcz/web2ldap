# -*- coding: utf-8 -*-
"""
Module web2ldapcnf
(c) by Michael Stroeder <michael@stroeder.com>

Some variables to configure the basic behaviour of web2ldap.py
This directory should reside in /etc/web2ldap on Unix systems or
either %SystemRoot%\web2ldap or %windir%\web2ldap on Windows systems.
All code must be valid Python syntax.
"""

import sys,os

# Directory where web2ldap is started
web2ldap_dir = os.path.dirname(os.path.dirname(__file__))

# Default directory for [web2ldap]/var
var_dir = os.path.join(web2ldap_dir,'var')
#var_dir = '/var'

# Default directory for [web2ldap]/etc
etc_dir = os.path.join(web2ldap_dir,'etc')
#etc_dir = '/etc'

# Default directory for [web2ldap]/etc/web2ldap/templates
templates_dir = os.path.join(etc_dir,os.path.join('web2ldap','templates'))

# Several default sub-directories in [web2ldap]/var
for var_subdir in ['run','log','state']:
  vars()['var_'+var_subdir] = os.path.join(var_dir,var_subdir)

import web2ldapcnf.misc,web2ldapcnf.hosts

try:
  import web2ldapcnf.local
except ImportError,e:
  sys.stderr.write('WARNING: Importing local config failed: %s\n' % (str(e)))
