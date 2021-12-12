# -*- coding: ascii -*-
"""
web2ldap.wsgi -- WSGI app wrapper eventually starting a stand-alone HTTP server

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import sys
import os
import time
import warnings
import wsgiref.util
import wsgiref.simple_server

# this has to be done before import module package ldap0
os.environ['LDAPNOINIT'] = '1'
import ldap0
import ldap0.functions

# import config after extending Python module path
import web2ldapcnf

from . import ETC_DIR
from .log import logger
from .web.wsgi import (
    AppResponse,
    W2lWSGIServer,
    W2lWSGIRequestHandler,
)
from .checkinst import check_inst
from .app.handler import AppHandler
from .app.session import session_store

check_inst()

########################################################################
# Initialize some constants
########################################################################

logger.debug('End of module %s', __name__)

# Raise UnicodeError instead of output of UnicodeWarning
warnings.filterwarnings(action="error", category=UnicodeWarning)

ldap0._trace_level = web2ldapcnf.ldap_trace_level
ldap0.functions.set_option(ldap0.OPT_DEBUG_LEVEL, web2ldapcnf.ldap_opt_debug_level)
ldap0.functions.set_option(ldap0.OPT_RESTART, 0)
ldap0.functions.set_option(ldap0.OPT_DEREF, 0)
ldap0.functions.set_option(ldap0.OPT_REFERRALS, 0)


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
            ETC_DIR,
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
    app = AppHandler(environ, outf)
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
        port_arg = sys.argv[1]
    elif len(sys.argv) == 3:
        port_arg = sys.argv[2]
        host_arg = sys.argv[1]
    else:
        raise SystemExit('Expected at most 2 optional arguments: [[host] port]')
    try:
        port_arg = int(port_arg)
    except ValueError:
        raise SystemExit(
            'Argument for port must be valid integer literal, was {0!r}'.format(port_arg)
        )
    logger.debug('Start listening for http://%s:%s/web2ldap', host_arg, port_arg)
    try:
        with wsgiref.simple_server.make_server(
                host_arg,
                port_arg,
                application,
                server_class=W2lWSGIServer,
                handler_class=W2lWSGIRequestHandler,
            ) as httpd:
            host, port = httpd.socket.getsockname()
            logger.info('Serving http://%s:%s/web2ldap', host, port)
            httpd.serve_forever()
    except (KeyboardInterrupt, SystemExit) as exit_exc:
        logger.debug('Caught %s in run_standalone()', exit_exc.__class__.__name__)
    except OSError as err:
        logger.error('Error starting service http://%s:%s/web2ldap: %s', host_arg, port_arg, err)
        raise SystemExit('Exiting because of OS error')
    # Stop clean-up thread
    session_store().expiry_thread.stop()
    logger.info('Stopped service http://%s:%s/web2ldap', host, port)
    # end of run_standalone()


if __name__ == '__main__':
    run_standalone()
