# -*- coding: utf-8 -*-
"""
msHTTPHandler.py - class for handling HTTP requests
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
import posixpath
import stat
import socket
import string
import SimpleHTTPServer
import urllib
from time import strftime,gmtime

from netaddr import IPAddress,IPNetwork

import web2ldap.msbase
from web2ldap.__about__ import __version__


def get_mime_types(mime_types_pathname):
  """
  Return dictionary with MIME types either read from file
  mime_types_pathname or a minimal default dictionay
  """
  # MIME-mapping
  if mime_types_pathname and os.path.isfile(mime_types_pathname):
    # Read mapping from file
    print 'Read MIME-type mapping from file %s.' % (mime_types_pathname)
    import mimetypes
    extensions_map = mimetypes.read_mime_types(mime_types_pathname)
    extensions_map[''] = 'text/plain' # Default, *must* be present
  else:
    # Define very simple default mapping suitable for our needs
    extensions_map = {
      '': 'text/plain',   # Default, *must* be present
      '.html': 'text/html',
      '.htm': 'text/html',
      '.gif': 'image/gif',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.css': 'text/css',
    }
  return extensions_map

class HTTPHandlerClass(SimpleHTTPServer.SimpleHTTPRequestHandler):
  """
  Sub-class for serving HTTP requests
  """
  script_name = None # must be overloaded
  server_signature = ''
  # server_env should be overloaded
  server_env = {
    'SERVER_SOFTWARE':'msHTTPHandler %s' % __version__,
    'DOCUMENT_ROOT':os.sep,
  }
  dir_listing_allowed = 0
  access_allowed   = map(IPNetwork,['127.0.0.1/255.0.0.0'])
  # Log file objects should be overloaded if running detached
  access_log = sys.stdout
  error_log = sys.stderr
  debug_log = sys.stdout
  extensions_map = get_mime_types('')
  reverse_lookups = 0

  # Make sure the connection is closed
  def finish(self):
    SimpleHTTPServer.SimpleHTTPRequestHandler.finish(self)
    self.connection.close()

  def translate_path(self,path):
    path = posixpath.normpath(urllib.unquote(path))
    words = filter(None,path.split('/'))
    path = self.server_env['DOCUMENT_ROOT']
    for word in words:
      path = os.path.join(path,word)
    return path

  def address_string(self):
    host, _ = self.client_address
    if self.reverse_lookups:
      return socket.getfqdn(host)
    else:
      return host

  def log_error(self, fmt, *args):
    """Log error messages"""
    self.error_log.write(
      "%s - - [%s] %s\n" % (
        self.address_string(),
        self.log_date_time_string(),
        fmt % args
      )
    )
    self.error_log.flush()

  def log_message(self, fmt, *args):
    """Log all access messages"""
    self.access_log.write(
      "%s - - [%s] %s\n" % (
          self.address_string(),
          self.log_date_time_string(),
          fmt % args
      )
    )
    self.access_log.flush()

  def log_request(self, code='-', size='-'):
      """Log an accepted request."""
      if code!=400:
        referer = self.headers.getheader('Referer','-')
        userAgent = self.headers.getheader('User-Agent','-')
      else:
        referer = '-';userAgent = '-'
      self.log_message(
        '"%s" %s %s "%s" "%s"',
        self.requestline,
        code,
        size,
        referer,
        userAgent
      )

  # Return usual CGI-BIN environment of current request as dictionary
  def get_http_env(self):
    rest = self.path[1:]
    i = string.find(rest, '?')
    if i >= 0:
        rest, query = rest[:i], rest[i+1:]
    else:
        query = ''
    i = string.find(rest, '/')
    if i >= 0:
        rest = rest[i:]
    else:
        rest = ''

    # env is the connection-dependent environment
    env = {}
    env.update(self.server_env)
    env['SERVER_NAME'] = self.server.server_name
    env['SERVER_PORT'] = str(self.server.server_port)
    env['CONTENT_TYPE'] = self.headers.typeheader or self.headers.type
    env['REQUEST_METHOD'] = self.command
    env['SCRIPT_NAME'] = self.script_name
    env['PATH_INFO'] = urllib.unquote(rest)
    env['QUERY_STRING'] = query
    env['REMOTE_ADDR'] = self.client_address[0]
    env['REMOTE_PORT'] = self.client_address[1]
    env['SCRIPT_FILENAME'] = sys.argv[0]
    env['REQUEST_URI'] = self.path[1:]
    for envitem in [
      ('Content-length','CONTENT_LENGTH'),
      ('User-Agent','HTTP_USER_AGENT'),
      ('Accept','HTTP_ACCEPT'),
      ('Accept-Charset','HTTP_ACCEPT_CHARSET'),
      ('Accept-Encoding','HTTP_ACCEPT_ENCODING'),
      ('Accept-Language','HTTP_ACCEPT_LANGUAGE'),
      ('Referer','HTTP_REFERER'),
      ('Connection','HTTP_CONNECTION'),
      ('Cookie','HTTP_COOKIE'),
      ('Host','HTTP_HOST'),
      ('Forwarded-For','HTTP_FORWARDED_FOR'),
      ('X-Forwarded-For','HTTP_X_FORWARDED_FOR'),
      ('X-Real-IP','HTTP_X_REAL_IP'),
    ]:
      http_header_value = self.headers.getheader(envitem[0])
      if http_header_value:
        env[envitem[1]] = http_header_value

    # SERVER_SIGNATURE is built with string template and all connection data
    disp_env = web2ldap.msbase.DefaultDict(env,'')
    env['SERVER_SIGNATURE'] = self.server_signature % disp_env

    return env

  # Checks if remote IP address is allowed to access
  def check_IPAdress(self):
    a = IPAddress(self.client_address[0])
    for n in self.access_allowed:
      if a in n:
        return True
    return False

  def is_webapp(self):
    """Determine if the web application is accessed."""
    if len(self.path)<len(self.script_name):
      return 0
    elif self.path==self.script_name:
      return 1
    elif self.path.startswith(self.script_name) and \
         self.path[len(self.script_name)] in ['?','/']:
      return 1
    else:
      return 0

  def list_directory(self,path):
    """List directory if allowed."""
    if self.dir_listing_allowed:
      return SimpleHTTPServer.SimpleHTTPRequestHandler.list_directory(self,path)
    else:
      self.send_error(403,"No permission to list directory")
      return None

  def do_POST(self):
    """Serve a POST request."""
    if not self.check_IPAdress():
      self.send_error(403,"Access denied")
      return
    if self.is_webapp():
      self.run_app(self.get_http_env())
    else:
      self.send_error(405,"POST only allowed for web application")

  def do_HEAD(self):
    """Serve a GET request."""
    if not self.check_IPAdress():
      self.send_error(403,"Access denied")
      return
    if self.is_webapp():
      self.send_error(405,"HEAD not supported by web application")
    else:
      SimpleHTTPServer.SimpleHTTPRequestHandler.do_HEAD(self)

  def do_GET(self):
    """Serve a GET request."""
    if not self.check_IPAdress():
      self.send_error(403,"Access denied")
      return
    if self.is_webapp():
      self.run_app(self.get_http_env())
    else:
      SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

  def run_app(self,http_env):
    """Start web application itself"""
    # Send start of HTTP response header
    self.send_response(200, "%s output follows" % (
        self.server_env['SERVER_SOFTWARE']
      )
    )
    return

  def send_head(self):
      """Common code for GET and HEAD commands.

      This sends the response code and MIME headers.

      Return value is either a file object (which has to be copied
      to the outputfile by the caller unless the command was HEAD,
      and must be closed by the caller under all circumstances), or
      None, in which case the caller has nothing further to do.

      """
      path = self.translate_path(self.path)
      f = None
      try:
          os_path_isdir_path = os.path.isdir(path)
      except TypeError:
          self.send_error(400, "Bad request")
          return None
      if os_path_isdir_path:
          for index in "index.html", "index.htm":
              index = os.path.join(path, index)
              if os.path.exists(index):
                  path = index
                  break
          else:
              return self.list_directory(path)
      ctype = self.guess_type(path)
      if ctype.startswith('text/'):
          mode = 'r'
      else:
          mode = 'rb'
      try:
          f = open(path, mode)
      except IOError:
          self.send_error(404, "File not found")
          return None
      self.send_response(200)
      self.send_header('Content-type', ctype)
      self.send_header('Pragma', 'cache')
      self.send_header('Last-modified', strftime(
        '%a, %d %b %Y %H:%M:%S GMT',
        gmtime(os.fstat(f.fileno())[stat.ST_MTIME])
      ))
      self.end_headers()
      return f

