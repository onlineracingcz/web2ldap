# -*- coding: utf-8 -*-
"""
web2ldap.wsgi -- WSGI app wrapper eventually starting a stand-alone HTTP server
"""

from __future__ import absolute_import

import sys
import os
import SocketServer
import time
import wsgiref.util
import wsgiref.simple_server

import web2ldap.app.core
from web2ldap.log import logger
import web2ldap.app.handler
import web2ldapcnf

BASE_URL = '/web2ldap'


class W2lWSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    """
    custom WSGIServer class
    """


class W2lWSGIServer(wsgiref.simple_server.WSGIServer, SocketServer.ThreadingMixIn):
    """
    custom WSGIServer class
    """


class AppResponse(object):
    """
    Application response class as file-like object
    """

    def __init__(self):
        self._seek = 0
        self._bytelen = 0
        self._lines = []
        self.headers = []

    def set_headers(self, headers):
        """
        set all HTTP headers at once
        """
        self.headers = headers

    def write(self, buf):
        """
        file-like method
        """
        assert isinstance(buf, str), TypeError('expected string for buf, but got %r', buf)
        self._lines.append(buf)
        self._seek += 1
        self._bytelen += len(buf)

    def close(self):
        """
        file-like method
        """
        del self._seek
        del self._lines


def application(environ, start_response):
    """
    the main WSGI application function
    """
    if environ['PATH_INFO'].startswith('/css/web2ldap'):
        css_filename = os.path.join(
            web2ldapcnf.etc_dir,
            'css',
            os.path.basename(environ['PATH_INFO'])
        )
        try:
            css_size = os.stat(css_filename).st_size
            css_file = open(css_filename, 'rb')
            css_http_headers = [
                ('Content-type', 'text/css'),
                ('Content-Length', str(css_size)),
            ]
            css_http_headers.extend(web2ldapcnf.http_headers.items())
            start_response('200 OK', css_http_headers)
        except (IOError, OSError) as err:
            logger.error('Error reading CSS file %r: %s', css_filename, err)
            start_response('404 not found', (('Content-type', 'text/plain')))
            return ['404 - CSS file not found.']
        else:
            return wsgiref.util.FileWrapper(css_file)
    if not environ['SCRIPT_NAME']:
        wsgiref.util.shift_path_info(environ)
    outf = AppResponse()
    app = web2ldap.app.handler.AppHandler(environ, outf)
    start_time = time.time()
    app.run()
    end_time = time.time()
    logger.debug(
        'Executing %s.run() took %0.3f secs',
        app.__class__.__name__,
        end_time-start_time,
    )
    outf.headers.append(('Content-Length', str(outf._bytelen)))
    start_response('200 OK', outf.headers)
    return outf._lines


def run_standalone():
    """
    start a simple stand-alone web server
    """
    logger.debug('Start stand-alone WSGI server')
    if len(sys.argv) == 1:
        host_arg = '127.0.0.1'
        port_arg = 1760
    elif len(sys.argv) == 2:
        host_arg = '127.0.0.1'
        port_arg = int(sys.argv[1])
    elif len(sys.argv) == 3:
        port_arg = int(sys.argv[2])
        host_arg = sys.argv[1]
    else:
        raise ValueError('Command-line arguments must be: [host] port')
    httpd = wsgiref.simple_server.make_server(
        host_arg,
        port_arg,
        application,
        server_class=W2lWSGIServer,
        handler_class=W2lWSGIRequestHandler,
    )
    host, port = httpd.socket.getsockname()
    logger.info('Serving http://%s:%s/web2ldap', host, port)
    try:
        # Serve until process is killed
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    logger.info('Stopping service http://%s:%s/web2ldap', host, port)
    # Stop clean-up thread
    web2ldap.app.session.cleanUpThread.enabled = 0
    return # end of run_standalone()

if __name__ == '__main__':
    run_standalone()
