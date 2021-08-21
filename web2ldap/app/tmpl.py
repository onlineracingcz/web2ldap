# -*- coding: utf-8 -*-
"""
web2ldap.app.tmpl - template file handling

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import os

from . import ErrorExit


def get_variant_filename(pathname, variantlist):
    """
    returns variant filename
    """
    checked_set = set()
    for val in variantlist:
        # Strip subtags
        val = val.lower().split('-', 1)[0]
        if val == 'en':
            variant_filename = pathname
        else:
            variant_filename = '.'.join((pathname, val))
        if val not in checked_set and os.path.isfile(variant_filename):
            break
        checked_set.add(val)
    else:
        variant_filename = pathname
    return variant_filename


def read_template(app, config_key, form_desc='', tmpl_filename=None):
    if not tmpl_filename:
        tmpl_filename = app.cfg_param(config_key, None)
    if not tmpl_filename:
        raise ErrorExit('No template specified for %s.' % (form_desc))
    tmpl_filename = get_variant_filename(tmpl_filename, app.form.accept_language)
    try:
        # Read template from file
        with open(tmpl_filename, 'rb') as tmpl_fileobj:
            tmpl_str = tmpl_fileobj.read().decode('utf-8')
    except IOError:
        raise ErrorExit('I/O error during reading %s template file.' % (form_desc))
    return tmpl_str
