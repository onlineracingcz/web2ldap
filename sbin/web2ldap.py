#!/usr/bin/python2.7 -ROO
# -*- coding: utf-8 -*-
"""
sbin/web2ldap.py - startscript for running as stand-alone HTTP server

web2ldap -  web-based LDAP Client, see http://www.web2ldap.de
(c) by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import sys,os,signal

exec_startdir = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
sys.path.insert(0,os.path.join(exec_startdir,'pylib'))
sys.path.insert(0,os.path.join(exec_startdir,'etc','web2ldap'))

if os.name == 'posix':
  # For finding web2ldapcnf.py in /etc/web2ldap on Unix systems
  sys.path.append('/etc/web2ldap')

# Import configuration modules
import web2ldapcnf.misc,web2ldapcnf.standalone

# Extend sys.path with modules dirs from configuration
for i in web2ldapcnf.misc.pylibdirs:
  sys.path.insert(0,i)

# These imports have to be done after extending sys.path
import web2ldapcnf.plugins
import mssignals,msHTTPServer,w2lapp.handler

from w2lapp.handler import Web2ldapHTTPHandler

config_server_address,config_server_name = msHTTPServer.split_server_address(
  web2ldapcnf.standalone.bind_address,('127.0.0.1',1760)
)

server_address,server_name,run_detached,run_threaded,ssl_enabled,uid = \
  msHTTPServer.GetCommandlineParams(
    config_server_address,config_server_name,
    os.name == 'posix',
    1,
    0,
    web2ldapcnf.standalone.run_username
  )

# Set active signal handler for stand-alone mode
signal.signal(signal.SIGTERM,mssignals.TERMSignalHandler)

if run_detached:
  # Detach from console means logging to files.
  # Log files are opened before dropping privileges to avoid having to
  # grant write permission to log file directory to non-privileged user
  Web2ldapHTTPHandler.access_log = open(web2ldapcnf.standalone.access_log,'a',1)
  Web2ldapHTTPHandler.error_log = open(web2ldapcnf.standalone.error_log,'a',1)
  Web2ldapHTTPHandler.debug_log = open(web2ldapcnf.standalone.debug_log,'a',1)
  pid_file = open(web2ldapcnf.standalone.pid_file,'w')

# Change UID if one was defined
if (not uid is None) and (uid!=os.getuid()):
  try:
    os.setuid(uid)
    print 'Changed to UID %d.' % (uid)
  except os.error:
    print 'Error changing to UID %d! Aborting.' % (uid)
    sys.exit(1)

# Force use of a pseudo-random salt to make hash() values before forking
os.environ['PYTHONHASHSEED'] = 'random'

if run_detached:
  if os.fork():
    sys.exit(0)
  else:
    os.setsid()
    # Write PID to file. Has to be done after forking!
    pid_file.write(str(os.getpid()))
    pid_file.close()
    sys.stdin.close()
    sys.stdout.close()
    sys.stdout = Web2ldapHTTPHandler.debug_log
    sys.stderr.close()
    sys.stderr = Web2ldapHTTPHandler.error_log
else:
  # Log to console
  Web2ldapHTTPHandler.access_log = sys.stdout
  Web2ldapHTTPHandler.error_log = sys.stderr
  Web2ldapHTTPHandler.debug_log = sys.stdout

# Start the clean-up thread
import w2lapp.session
w2lapp.session.cleanUpThread.start()

try:
  msHTTPServer.RunServer(
    Web2ldapHTTPHandler,
    server_address,
    server_name,
    run_detached,
    run_threaded,
    0
  )
except KeyboardInterrupt,SystemExit:
  # Stop clean-up thread
  w2lapp.session.cleanUpThread.enabled=0
  if run_detached:
    # Remove the PID file
    Web2ldapHTTPHandler.debug_log.write(
      'Trying to remove PID file %s\n' % (web2ldapcnf.standalone.pid_file)
    )
    os.remove(web2ldapcnf.standalone.pid_file)
