# -*- coding: utf-8 -*-
"""
web2ldap.httpserver - stand-alone single-web-application server
(c) by Michael Stroeder <michael@stroeder.com>

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
import getopt
import SocketServer
import socket
import traceback

from os import getuid

try:
  import pwd
except ImportError:
  pwd = None


def split_server_address(v,server_address):
  """
  Split a server address string host:port, with fall-back to port
  """
  adr = v.rsplit(':',1)
  if len(adr)==2:
    server_name = adr[0].strip()
    server_address = (
      socket.gethostbyname(server_name) or server_address[0],
      int(adr[1].strip()) or server_address[1]
    )
  elif len(adr)==1:
    server_name = server_address[0]
    server_address = server_address[0],int(v.strip())
  else:
    raise ValueError
  if server_address[0]=='0.0.0.0':
    server_name = socket.getfqdn()
  elif server_address[0]==server_name:
    h = socket.gethostbyaddr(server_name)
    hn_set = [h[0]]
    hn_set.extend(h[1])
    server_name = hn_set.pop(0)
    while hn_set:
      if not '.' in server_name:
        server_name = hn_set.pop(0)
      else:
        break
  return server_address,server_name


class HTTPServer(SocketServer.TCPServer):
  """
  Base class for a HTTP server.
  """

  def __init__(self, server_address, RequestHandlerClass):
    SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)

  def server_bind(self):
    """Override server_bind to set socket options."""
    self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    SocketServer.TCPServer.server_bind(self)

  def format_log(self,log_msg,client_address):
    return os.linesep.join(
      ['%s %s:%d %s\n' % (
        time.strftime(
          '%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time())
        ),
        client_address[0],client_address[1],
        log_msg,
      )]
    )

  def handle_request(self):
      """Handle one request, possibly blocking."""
      try:
          request, client_address = self.get_request()
      except socket.error:
          return
      if self.verify_request(request, client_address):
          try:
              self.process_request(request, client_address)
          except:
              self.handle_error(request, client_address)
              self.close_request(request)

  def handle_error(self,request,client_address):
      """
      Generic low-level handler for exceptions
      """
      exc_obj,exc_value,exc_traceback = sys.exc_info()
      if isinstance(exc_value,KeyboardInterrupt):
        raise KeyboardInterrupt
      elif isinstance(exc_value,IOError):
        if exc_value.errno==32 or exc_value.errno==104:
          # The user has aborted access and the remote
          # connection end-point is not available anymore
          sys.stdout.write(self.format_log(
            'IOError %s: User probably interrupted connection.' % (
              repr(exc_value.errno)),
              client_address
          ))
        elif exc_value.errno==24:
          # Ressource limit reached
          sys.stdout.write(self.format_log(
            str(exc_value),
            client_address
          ))
        else:
          sys.stderr.write(self.format_log(
            str(exc_value),
            client_address
          ))

      elif isinstance(exc_value,socket.error):
        sys.stderr.write(self.format_log(
          'Socket error: %s' % (repr(exc_value.args)),
          client_address
        ))
      else:
        sys.stderr.write(self.format_log(
          'Unhandled exception:\n'+''.join(traceback.format_exception(exc_obj,exc_value,exc_traceback,20)),
          client_address
        ))
      # Avoid memory leaks
      exc_obj=None;exc_value=None;exc_traceback=None
      del exc_obj;del exc_value;del exc_traceback

try:
  import threading
except ImportError:
  ThreadingHTTPServer = HTTPServer
else:

  class HTTPThread(threading.Thread):
    """Thread class for HTTP handler thread"""
    def __init__(self,serverInstance,func,request,client_address,handle_error):
      self.serverInstance = serverInstance
      self._func=func
      self._request=request
      self._client_address=client_address
      self._handle_error=handle_error
      self.started=time.time()
      threading.Thread.__init__(self)
      self.setName(
        self.__class__.__name__+self.getName()[6:]
      )
    def __repr__(self):
      return '%s:%d - %s started %s' % (
        self._client_address[0],self._client_address[1],
        self.getName(),
        time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(self.started)),
      )
    def isAlive(self):
      """Check if remote end is still alive by sending empty string"""
      try:
        self._request.send("")
      except IOError:
        return 0
      else:
        return 1

    def run(self):
      try:
        try:
          apply(
            self._func,
            (self._request,self._client_address)
          )
        except:
          apply(
            self._handle_error,
            (self._request,self._client_address)
          )
          raise
      finally:
        self.serverInstance.close_request(self._request)
      del self.serverInstance

  class ThreadingHTTPServer(HTTPServer):

    def process_request(self, request, client_address):
      """Start a new thread to process the request."""
      t = HTTPThread(
        self,self.finish_request,request,client_address,self.handle_error
      )
      t.start()
    if SocketServer.__version__<='0.3':
      def close_request(self,request):
        """Work around bug in SocketServer.BaseServer.handle_request()
        of Python 2.1"""
        return


def PrintUsage(ErrorMsg=''):
  print """
usage: %s [options]

Options:

-h or -?
    Print out this message

-d on/off
    demon mode (detach from console)
    Default: on

-t on/off
    Run multi-threaded HTTP server.
    If starting multi-threaded fails the script falls
    backs to running a single-threaded HTTP server.
    Default: on

-s on/off
    Have SSL on/off.

-l [hostname:]port
    Listen to hostname:port. Either hostname:port or
    port is allowed.
    Default: your hostname:1760

-u numeric uid or username
    Switch to given UID or username after binding
    to socket.
    Default:
    Current UID if not started as root.
    nobody if started as root.

""" % (sys.argv[0])
  if ErrorMsg:
    print '*** Error: %s' % (ErrorMsg)
  sys.exit(1)


# Get the server startup parameters from defaults and command-line options
def GetCommandlineParams(
  server_address,
  server_name,
  run_detached=1,
  run_threaded=0,
  ssl_enabled=0,
  uidparam=''
):

  uid = uidparam

  # Get startup arguments from command-line options
  try:
    optlist,_=getopt.getopt(sys.argv[1:],"?hs:d:t:u:l:")
  except getopt.error as e:
    PrintUsage(str(e))
    sys.exit(1)

  for k,v in optlist:

    if k=="-d":
      flag = v.lower()
      if flag in ['on','off']:
        run_detached = (flag=='on') and (os.name=='posix')
      else:
        PrintUsage('Detach option (option -d) must be on or off.')

    if k=="-u":
      uidparam = v

    if k=="-l":
      try:
        server_address,server_name = split_server_address(v,server_address)
      except ValueError:
        PrintUsage('Bind address (option -l) has invalid format.')

    if k=="-t":
      flag = v.lower()
      if flag in ['on','off']:
        run_threaded = flag=='on'
      else:
        PrintUsage('Threading option (option -t) must be on or off.')

    if k=="-s":
      flag = v.lower()
      if flag in ['on','off']:
        ssl_enabled = flag=='on'
      else:
        PrintUsage('SSL option (option -s) must be on or off.')

    if (k=="-h") or (k=="-?"):
      PrintUsage()

  uid = getuid()

  if uid is None:
    print 'Warning: Changing UID is not available on this platform'

  else:
    if uid==0 or os.geteuid()==0:
      try:
        uid = int(uidparam)
      except ValueError:
        if pwd is None:
          uid = None
        if os.getuid()==0 or os.geteuid()==0:
          try:
            uid = pwd.getpwnam(uidparam).pw_uid
          except AttributeError:
            print 'Warning: Module pwd not usable on your system'
            uid = 65534
          except KeyError:
            print 'Warning: User %s does not exist on your system' % (uidparam)
            uid = 65534
    else:
      print 'Warning: Changing user is only possible as root'
    try:
      user_name = pwd.getpwuid(uid).pw_name
    except (KeyError,AttributeError):
      user_name = str(uid)
    print 'Run as %s (%s)' % (user_name,uid)

  return (
    (server_address[0],server_address[1]),
    server_name,
    run_detached,
    run_threaded,
    ssl_enabled,uid
  )


def RunServer(
  HTTPHandler,
  server_address,
  server_name,
  run_detached,
  run_threaded,
  ssl_enabled=0,
  ssl_randfile='',
  ssl_Protocols=[],
  ssl_CertificateFile='',
  ssl_CertificateKeyFile='',
  ssl_CACertificateFile='',
  ssl_VerifyClient=0,
  ssl_VerifyDepth=1,
):

  # We will never read from stdin => close for security reasons
  sys.stdin.close()

  # Change current directory
  if not os.path.isdir(os.path.abspath(HTTPHandler.server_env['DOCUMENT_ROOT'])):
    print 'Warning: document_root %s does not exist.' % (
      HTTPHandler.server_env['DOCUMENT_ROOT']
    )

  if ssl_enabled:

    PrintUsage('SSL currently not supported!')

  ServerClass = {
    0:HTTPServer,1:ThreadingHTTPServer
  }[run_threaded]
  ServerInstance = ServerClass(server_address,HTTPHandler)

  # Set the server name
  try:
    ServerInstance.server_name = server_name or socket.gethostbyaddr(socket.gethostbyname(ServerInstance.server_address[0]))[0]
  except socket.error:
    try:
      ServerInstance.server_name = socket.getfqdn()
    except socket.error:
      ServerInstance.server_name = ServerInstance.server_address[0]
  # Set the server port
  ServerInstance.server_port = ServerInstance.server_address[1]

  # Write startup info to stderr
  sys.stderr.write(
    '%s Started %s web server on %s:%s with SSL %s\n' % (
      time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())),
      {
        0:'single-threaded',1:'multi-threaded'
      }[run_threaded],
      ServerInstance.server_name,
      ServerInstance.server_port,
      {0:'disabled',1:'enabled'}[ssl_enabled],
    )
  )
  sys.stderr.write('Accepted IP address ranges: %s\n' % (repr(HTTPHandler.access_allowed)))

  print """
Point your favourite browser to

%s://%s:%s%s

to access the web application.""" % (
  {0:'http',1:'https'}[ssl_enabled],
  ServerInstance.server_name,
  ServerInstance.server_port,
  HTTPHandler.script_name
)
  if run_detached:
    sys.stdout = HTTPHandler.debug_log
    sys.stderr = HTTPHandler.error_log
    try:
      ServerInstance.serve_forever()
    finally:
      ServerInstance.socket.close()
  else:
    try:
      ServerInstance.serve_forever()
    except KeyboardInterrupt:
      print 'Shutting down web server'
      ServerInstance.socket.close()

  return # RunServer()


def start():

  exec_startdir = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
  sys.path.insert(0,os.path.join(exec_startdir,'etc','web2ldap'))

  if os.name == 'posix':
    # For finding web2ldapcnf.py in /etc/web2ldap on Unix systems
    sys.path.append('/etc/web2ldap')

  # Import configuration modules
  import web2ldapcnf.misc,web2ldapcnf.standalone
  from web2ldap.httphandler import HTTPHandler
  from web2ldap.app.session import cleanUpThread

  # These imports have to be done after extending sys.path
  import web2ldapcnf.plugins

  config_server_address,config_server_name = split_server_address(
    web2ldapcnf.standalone.bind_address,('127.0.0.1',1760)
  )

  server_address,server_name,run_detached,run_threaded,ssl_enabled,uid = \
    GetCommandlineParams(
      config_server_address,config_server_name,
      os.name == 'posix',
      1,
      0,
      web2ldapcnf.standalone.run_username
    )

  if run_detached:
    # Detach from console means logging to files.
    # Log files are opened before dropping privileges to avoid having to
    # grant write permission to log file directory to non-privileged user
    HTTPHandler.access_log = open(web2ldapcnf.standalone.access_log,'a',1)
    HTTPHandler.error_log = open(web2ldapcnf.standalone.error_log,'a',1)
    HTTPHandler.debug_log = open(web2ldapcnf.standalone.debug_log,'a',1)
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
      sys.stdout = HTTPHandler.debug_log
      sys.stderr.close()
      sys.stderr = HTTPHandler.error_log
  else:
    # Log to console
    HTTPHandler.access_log = sys.stdout
    HTTPHandler.error_log = sys.stderr
    HTTPHandler.debug_log = sys.stdout

  # Start the clean-up thread
  cleanUpThread.start()

  try:
    RunServer(
      HTTPHandler,
      server_address,
      server_name,
      run_detached,
      run_threaded,
      0
    )
  except KeyboardInterrupt,SystemExit:
    # Stop clean-up thread
    cleanUpThread.enabled = 0
    if run_detached:
      # Remove the PID file
      HTTPHandler.debug_log.write(
        'Trying to remove PID file %s\n' % (web2ldapcnf.standalone.pid_file)
      )
      os.remove(web2ldapcnf.standalone.pid_file)


if __name__ == '__main__':
    start()
