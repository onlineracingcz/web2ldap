# -*- coding: utf-8 -*-
"""
web2ldap application package

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""


def cmp(a, b):
    """
    Workaround to have cmp() like in Python 2
    """
    return bool(a > b) - bool(a < b)