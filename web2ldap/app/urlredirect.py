# -*- coding: utf-8 -*-
"""
web2ldap.app.urlredirect: handle URL redirection

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import urllib.parse

import web2ldapcnf

from .session import session_store


def w2l_urlredirect(app):
    # accept configured trusted redirect targets no matter what
    redirect_ok = app.form.query_string in web2ldapcnf.good_redirect_targets
    if not redirect_ok:
        # Check for valid target URL syntax
        try:
            tu = urllib.parse.urlparse(app.form.query_string)
        except Exception:
            redirect_ok = False
            error_msg = 'Rejected non-parseable redirect URL!'
        else:
            redirect_ok = True
            # further checks
            if not tu or not tu.scheme or not tu.netloc:
                redirect_ok = False
                error_msg = 'Rejected malformed/suspicious redirect URL!'
            # Check for valid session
            if app.sid not in session_store().sessiondict:
                redirect_ok = False
                error_msg = 'Rejected redirect without session-ID!'
    # finally send return redirect to browser
    if redirect_ok:
        # URL redirecting has absolutely nothing to do with rest
        app.url_redirect(
            'Redirecting to %s...' % (app.form.query_string),
            refresh_time=0,
            target_url=app.form.query_string,
        )
    else:
        app.url_redirect(error_msg)
    # end of w2l_urlredirect()
