# -*- coding: ascii -*-
"""
web2ldap.app.stats: Counter objects

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from collections import defaultdict

COMMAND_COUNT = defaultdict(lambda: 0)
