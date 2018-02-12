# -*- coding: utf-8 -*-
"""
web2ldap.wsgi -- WSGI app wrapper eventually starting a stand-alone HTTP server
"""

from __future__ import absolute_import

import os
import wsgiref.util
import wsgiref.simple_server

try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

import web2ldap.__about__
import web2ldap.app.cnf, web2ldap.app.handler

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

    def close(self):
        del self._seek
        del self._lines

    def rest(self):
        return self._lines[self._seek:]


def application(environ, start_response):
    if not environ['SCRIPT_NAME']:
        wsgiref.util.shift_path_info(environ)
    outf = AppResponse()
    app = web2ldap.app.handler.AppHandler(environ, outf)
    app.run()
    outf.headers.append(('Content-Length', str(outf._bytelen)))
    start_response(
        '200 OK',
        outf.headers,
    )
    return outf._lines


def start_server():
    import wsgiref.simple_server
    httpd = wsgiref.simple_server.make_server(
        '127.0.0.1',
        1760,
        application,
    )
    host, port = httpd.socket.getsockname()
    print "Serving http://%s:%s/web2ldap" % (host, port)
    try:
        # Serve until process is killed
        httpd.serve_forever()
    except KeyboardInterrupt:
        print "Stopping service on port 1760..."


if __name__ == '__main__':
    start_server()
