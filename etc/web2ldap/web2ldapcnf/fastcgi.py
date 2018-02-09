# -*- coding: utf-8 -*-
"""
web2ldapcnf/fastcgi.py
Options for running web2ldap as FastCGI server

(c) by Michael Stroeder <michael@stroeder.com>
"""

# Leave this alone
import os,web2ldapcnf

# Run multi-threaded
# You might want to set this to 0 if you can configure your FastCGI
# environment with session affinity.
run_threaded = 1

# Path name of PID file (system-specific)
#pid_file = '/var/lib/apache2/fcgid/web2ldap-fastcgi.pid'
#pid_file = os.path.join(web2ldapcnf.var_run,'web2ldap-fcgi.pid')
pid_file = None

# Path name of error log file
# error_log = '/var/log/web2ldap/error_log'
# error_log = os.path.join(web2ldapcnf.var_log,'error_log')
error_log = None

# Path name of debug log file
# debug_log = '/var/log/web2ldap/debug_log'
# debug_log = os.path.join(web2ldapcnf.var_log,'debug_log')
debug_log = None

# Set a base URL of the application (handy for running via reverse proxy)
# Set None to let web2ldap determine the base URL automatically from
# CGI-BIN environment var SCRIPT_NAME
#base_url = 'http://localhost/web2ldap-fcgi'
base_url = None
