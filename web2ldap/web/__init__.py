# -*- coding: utf-8 -*-
"""
web2ldap.web - module package for low-level web programming

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""


def escape_html(val: str) -> str:
    """
    Escape all characters with a special meaning in HTML
    to appropriate character tags
    """
    val = val.replace('&', '&#38;')
    val = val.replace('<', '&#60;')
    val = val.replace('>', '&#62;')
    val = val.replace("'", '&#39;')
    val = val.replace('"', '&#34;')
    val = val.replace(':', '&#58;')
    val = val.replace('=', '&#61;')
    val = val.replace('{', '&#123;')
    val = val.replace('}', '&#125;')
    val = val.replace('(', '&#40;')
    val = val.replace(')', '&#41;')
    val = val.replace('`', '&#96;')
    return val
