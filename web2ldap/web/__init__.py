# -*- coding: ascii -*-
"""
web2ldap.web - module package for low-level web programming

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

# map for escape all HTML chars with str.translate()
HTML_ESCAPE_MAP = {
    ord(char): '&#%d;' % (ord(char))
    for char in ('&', '<', '>', "'", '"', ':', '=', '{', '}', '(', ',', '`')
}

def escape_html(val: str) -> str:
    """
    Escape all characters with a special meaning in HTML
    to appropriate character tags
    """
    return val.translate(HTML_ESCAPE_MAP)
