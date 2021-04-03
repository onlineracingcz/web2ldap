# -*- coding: utf-8 -*-
"""
web2ldap.app - module package of web2ldap application

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

class ErrorExit(Exception):
    """Base class for web2ldap application exceptions"""

    def __init__(self, Msg):
        assert isinstance(Msg, str), \
            TypeError("Type of argument 'Msg' must be str, was %r" % (Msg))
        self.Msg = Msg
