#!/usr/bin/python2.7 -ROO
# -*- coding: utf-8 -*-
"""
fcgi/web2ldap.py - stub script for running as FastCGI server

web2ldap -  web-based LDAP Client, see http://www.web2ldap.de
(c) by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import sys,os,signal,time,threading

exec_startdir = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
sys.path.insert(0,os.sep.join([exec_startdir,'etc','web2ldap']))
sys.path.insert(0,os.sep.join([exec_startdir,'pylib']))


if os.name == 'posix':
  # For finding web2ldapcnf.py in /etc/web2ldap on Unix systems
  sys.path.append('/etc/web2ldap')

# Import configuration modules
import web2ldapcnf.misc,web2ldapcnf.fastcgi

if web2ldapcnf.fastcgi.pid_file!=None:
  try:
    open(web2ldapcnf.fastcgi.pid_file,'w').write(str(os.getpid()))
  except Exception,e:
    sys.stderr.write('Warning: Creating PID file %s failed: %s\n' % (repr(web2ldapcnf.fastcgi.pid_file),str(e)))

# Extend sys.path with modules dirs from configuration
for i in web2ldapcnf.misc.pylibdirs:
  sys.path.insert(0,i)

# These imports have to be done after extending sys.path
import fcgi
import web2ldapcnf.plugins
import mssignals
import w2lapp.handler,w2lapp.core
from w2lapp.handler import AppHandler

# Redirect stderr/web error log and stdout if log files
# were specified in configuration
if web2ldapcnf.fastcgi.error_log:
  error_log = open(web2ldapcnf.fastcgi.error_log,'a',1)
  sys.stderr.close()
  sys.stderr = error_log
else:
  error_log = None
if web2ldapcnf.fastcgi.debug_log:
  sys.stdout.close()
  sys.stdout = open(web2ldapcnf.fastcgi.debug_log,'a',1)


def handle_request(req):
  """Function which handles a single request"""
  req.env['SCRIPT_NAME'] = web2ldapcnf.fastcgi.base_url or req.env['SCRIPT_NAME']
  try:
    app = AppHandler(req.inp,req.out,error_log or req.err,req.env)
    app.run()
  finally:
    req.Finish()


class FastCGIThread(threading.Thread):
  """Thread class for FastCGIServer threads"""

  def __init__(self,req):
    """create a new thread to handle request in req"""
    self._req = req
    threading.Thread.__init__(self)
    self.started=time.time()
    self.setName(
      self.__class__.__name__+self.getName()[6:]
    )

  def __repr__(self):
    return '%s:%s - %s started %s' % (
      self._req.env.get('REMOTE_ADDR','unknown'),
      self._req.env.get('REMOTE_PORT','unknown'),
      self.getName(),
      time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(self.started)),
    )

  def run(self):
    handle_request(self._req)


# Set active signal handler for FastCGI mode
signal.signal(signal.SIGTERM,mssignals.TERMSignalHandler)
signal.signal(signal.SIGUSR1,mssignals.USR1SignalHandler)
signal.signal(signal.SIGPIPE,mssignals.PIPESignalHandler)

# Start the clean-up thread
import w2lapp.session
w2lapp.session.cleanUpThread.start()

try:
  if web2ldapcnf.fastcgi.run_threaded:
    # Run multi-threaded
    while fcgi.isFCGI():
      req = fcgi.FCGI()
      t = FastCGIThread(req)
      t.start()
  else:
    # Run single-threaded
    while fcgi.isFCGI():
      req = fcgi.FCGI()
      handle_request(req)
except KeyboardInterrupt,SystemExit:
  # Stop clean-up thread
  w2lapp.session.cleanUpThread.enabled=0
  if web2ldapcnf.fastcgi.pid_file!=None:
    try:
      os.remove(web2ldapcnf.fastcgi.pid_file)
    except Exception,e:
      sys.stderr.write('Warning: Removing PID file %s failed: %s\n' % (repr(web2ldapcnf.fastcgi.pid_file),str(e)))
