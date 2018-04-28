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
web2ldap_dir = os.environ.get('WEB2LDAP_HOME', sys.prefix)

# Default directory for [web2ldap]/etc
etc_dir = os.environ.get('WEB2LDAP_ETC', os.path.join(web2ldap_dir,'etc','web2ldap'))
#etc_dir = '/etc/web2ldap'

# Default directory for [web2ldap]/etc/web2ldap/templates
templates_dir = os.path.join(etc_dir,'templates')

import web2ldapcnf.misc
import web2ldapcnf.hosts
import web2ldapcnf.plugins

try:
  import web2ldapcnf.local
except ImportError,e:
  sys.stderr.write('WARNING: Importing local config failed: %s\n' % (str(e)))
