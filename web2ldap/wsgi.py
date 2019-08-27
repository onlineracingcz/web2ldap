# -*- coding: utf-8 -*-
"""
web2ldap.wsgi -- WSGI app wrapper eventually starting a stand-alone HTTP server
"""

from __future__ import absolute_import

import sys
import os
import socketserver
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


class W2lWSGIServer(wsgiref.simple_server.WSGIServer, socketserver.ThreadingMixIn):
    """
    custom WSGIServer class
    """


class AppResponse(object):
    """
    Application response class as file-like object
    """

    def __init__(self):
        self.bytelen = 0
        self.lines = []
        self.headers = []

    def reset(self):
        """
        reset the output completely (e.g. in case of error message)
        """
        self.bytelen = 0
        del self.lines
        self.lines = []
        del self.headers
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
        self.lines.append(buf)
        self.bytelen += len(buf)

    def close(self):
        """
        file-like method
        """
        del self.lines


def application(environ, start_response):
    """
    the main WSGI application function
    """
    # check whether HTTP request method is valid
    if environ['REQUEST_METHOD'] not in {'POST', 'GET'}:
        logger.error('Invalid HTTP request method %r', environ['REQUEST_METHOD'])
        start_response('400 invalid request', (('Content-type', 'text/plain')))
        return ['400 - Invalid request.']
    # check URL path whether to deliver a static file
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
    app.run()
    logger.debug(
        'Executing %s.run() took %0.3f secs',
        app.__class__.__name__,
        time.time()-app.current_access_time,
    )
    outf.headers.append(('Content-Length', str(outf.bytelen)))
    start_response('200 OK', outf.headers)
    return outf.lines


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
    # end of run_standalone()


if __name__ == '__main__':
    run_standalone()
