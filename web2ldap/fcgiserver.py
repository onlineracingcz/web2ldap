#!/usr/bin/python2.7 -ROO
# -*- coding: utf-8 -*-
"""
fcgi/web2ldap.py - stub script for running as FastCGI server

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import sys
import os
import time
import threading


def start():

  exec_startdir = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
  sys.path.insert(0,os.sep.join([exec_startdir,'etc','web2ldap']))

  if os.name == 'posix':
    # For finding web2ldapcnf.py in /etc/web2ldap on Unix systems
    sys.path.append('/etc/web2ldap')

  # Import configuration modules
  import web2ldapcnf.misc,web2ldapcnf.fastcgi
  from web2ldap.app.handler import AppHandler
  from web2ldap.app.session import cleanUpThread

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


  # Start the clean-up thread
  cleanUpThread.start()

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
    cleanUpThread.enabled=0
    if web2ldapcnf.fastcgi.pid_file!=None:
      try:
        os.remove(web2ldapcnf.fastcgi.pid_file)
      except Exception,e:
        sys.stderr.write('Warning: Removing PID file %s failed: %s\n' % (repr(web2ldapcnf.fastcgi.pid_file),str(e)))


if __name__ == '__main__':
    start()
