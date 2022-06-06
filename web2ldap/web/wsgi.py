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

import socketserver
import wsgiref.util
import wsgiref.simple_server


class W2lWSGIRequestHandler(wsgiref.simple_server.WSGIRequestHandler):
    """
    custom WSGIServer class
    """


class W2lWSGIServer(wsgiref.simple_server.WSGIServer, socketserver.ThreadingMixIn):
    """
    custom WSGIServer class
    """


class WSGIBytesWrapper:

    def __init__(self, outf):
        self._outf = outf

    def set_headers(self, headers):
        self._outf.set_headers(headers)

    def write(self, buf):
        self._outf.write_bytes(buf)


class AppResponse:
    """
    Application response class as file-like object
    """

    def __init__(self):
        self.bytelen = 0
        self.lines = []
        self.headers = []
        self.reset()
        self.charset = 'utf-8'

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
        assert isinstance(buf, str), TypeError('expected str for buf, but got %r', buf)
        self.write_bytes(buf.encode(self.charset, 'replace'))

    def write_bytes(self, buf):
        assert isinstance(buf, bytes), TypeError('expected bytes for buf, but got %r', buf)
        self.lines.append(buf)
        self.bytelen += len(buf)

    def close(self):
        """
        file-like method
        """
        del self.lines
