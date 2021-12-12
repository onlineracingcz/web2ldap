# -*- coding: ascii -*-
"""
web2ldap.app - module package of web2ldap application

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

class ErrorExit(Exception):
    """
    Base class for web2ldap application exceptions reaching the UI
    """

    def __init__(self, error_message):
        assert isinstance(error_message, str), TypeError(
            "Argument 'error_message' must be str, got %r" % (error_message)
        )
        Exception.__init__(self)
        self.error_message = error_message
