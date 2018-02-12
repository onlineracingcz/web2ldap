# -*- coding: utf-8 -*-
"""
web2ldap.wsgi -- WSGI app wrapper eventually starting a stand-alone HTTP server
"""

from __future__ import absolute_import

import sys
import pprint
from wsgiref.util import FileWrapper
try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

import web2ldap.app.handler

BASE_URL = '/web2ldap'


class AppResponse(file):

    def __init__(self):
        self._seek = 0
        self._bytelen = 0
        self._lines = []
        self.headers = []

    def set_headers(self, headers):
        self.headers = headers

    def write(self, buf):
        self._lines.append(buf)
        self._seek += 1
        self._bytelen += len(buf)

    def seek(self, spos):
        self._seek = spos

    def readline(self):
        try:
            line = self._lines[self._seek]
        except IndexError:
            return ''
        self._seek += 1
        return line        

    def flush(self):
        pass

    def close(self):
        del self._seek
        del self._lines

    def rest(self):
        return self._lines[self._seek:]


def application(environ, start_response):
    if not environ['PATH_INFO'].startswith('/web2ldap'):
        start_response(
            '404 Not found!',
            [],
        )
        return []
    environ['SCRIPT_NAME'] = BASE_URL
    environ['PATH_INFO'] = environ['PATH_INFO'][len(environ['SCRIPT_NAME']):]
    outf = AppResponse()
    app = web2ldap.app.handler.AppHandler(
        environ['wsgi.input'],
        outf,
        environ,
    )
    app.run()
    outf.headers.append(('Content-Length', str(outf._bytelen)))
    start_response(
        '200 OK',
        outf.headers,
    )
    return outf._lines


def start_server():
    import wsgiref.simple_server
    httpd = wsgiref.simple_server.make_server('', 1760, application)
    print "Serving on port 1760..."
    try:
        # Serve until process is killed
        httpd.serve_forever()
    except KeyboardInterrupt:
        print "Stopping service on port 1760..."


if __name__ == '__main__':
    start_server()
