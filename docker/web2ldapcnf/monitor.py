# -*- coding: utf-8 -*-
"""
web2ldapcnf/monitor.py
Options for web2ldap's monitor page

(c) by Michael Stroeder <michael@stroeder.com>

Note that these options does not affect anything else than web2ldap/monitor
"""

# List of accepted address/net mask strings of
# accepted client addresses.
# Use [u'0.0.0.0/0.0.0.0','::0'] to allow access to every client but think twice!
# IPv6 network addresses without brackets!
access_allowed = [
  u'0.0.0.0/0.0.0.0','::0',
]
