# -*- coding: utf-8 -*-
"""
ldaputil - several LDAP-related utility classes/functions

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import re

import ldap0
import ldap0.sasl
import ldap0.dn
import ldap0.filter

from . import passwd
from . import extldapurl
from . import oidreg


AD_LDAP49_ERROR_CODES = {
    0x525: 'user not found',
    0x52e: 'invalid credentials',
    0x530: 'not permitted to logon at this time',
    0x531: 'not permitted to logon at this workstation',
    0x532: 'password expired',
    0x533: 'account disabled',
    0x701: 'account expired',
    0x773: 'user must reset password',
    0x775: 'user account locked',
}
AD_LDAP49_ERROR_PREFIX = b'AcceptSecurityContext error, data '

ATTR_TYPE_PATTERN = u'[\\w;.-]+(;[\\w_-]+)*'
ATTR_VALUE_PATTERN = u'(([^,]|\\\\,)+|".*?")'
RDN_PATTERN = ATTR_TYPE_PATTERN + u'[ ]*=[ ]*' + ATTR_VALUE_PATTERN


def has_subordinates(entry, default=True) -> bool:
    """
    Try to determine from entry's attributes whether there are subordinates.

    :default: will be returned if there is no operational attribute clearly
    specifying whether there are no subordinate entries.
    """
    if 'hasSubordinates' in entry:
        hs_attr = entry['hasSubordinates'][0].upper()
        if isinstance(hs_attr, bytes):
            if hs_attr == b'TRUE':
                return True
            if hs_attr == b'FALSE':
                return False
        else:
            if hs_attr == 'TRUE':
                return True
            if hs_attr == 'FALSE':
                return False
        # when reaching here attribute hasSubordinates contains garbage
        # => LDAP server vendor sucks, proceed
    try:
        res = int(
            entry.get(
                'subordinateCount',
                entry.get(
                    'numAllSubordinates',
                    entry['msDS-Approx-Immed-Subordinates']
                ))[0]
        ) > 0
    except (ValueError, KeyError):
        res = default
    return res


def logdb_filter(logdb_objectclass, dn, entry_uuid=None):
    """
    returns a filter for querying a changelog or accesslog DB for
    changes to a certain entry referenced by :dn: or :entry_uuid:
    """
    if logdb_objectclass.startswith(u'audit'):
        logdb_dn_attr = u'reqDN'
        logdb_entryuuid_attr = u'reqEntryUUID'
    elif logdb_objectclass.startswith(u'change'):
        logdb_dn_attr = u'targetDN'
        logdb_entryuuid_attr = u'targetEntryUUID'
    else:
        raise ValueError('Unknown logdb object class %r' % (logdb_objectclass))
    if entry_uuid:
        target_filterstr = u'(|(%s=%s)(%s=%s))' % (
            logdb_dn_attr,
            ldap0.filter.escape_str(dn),
            logdb_entryuuid_attr,
            ldap0.filter.escape_str(entry_uuid),
        )
    else:
        target_filterstr = u'(%s=%s)' % (
            logdb_dn_attr,
            ldap0.filter.escape_str(dn),
        )
    logdb_filterstr = u'(&(objectClass=%s)%s)' % (
        logdb_objectclass,
        target_filterstr,
    )
    return logdb_filterstr
