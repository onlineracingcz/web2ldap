# -*- coding: utf-8 -*-
"""
ldaputil - several LDAP-related utility classes/functions

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2020 by Michael Stroeder <michael@stroeder.com>

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

attr_type_pattern = u'[\\w;.-]+(;[\\w_-]+)*'
attr_value_pattern = u'(([^,]|\\\\,)+|".*?")'
rdn_pattern = attr_type_pattern + u'[ ]*=[ ]*' + attr_value_pattern


def ietf_oid_str(oid):
    """
    Returns normalized IETF string representation of oid
    """
    vl = oid.split(' ')
    res = []
    for vs in vl:
        if vs:
            vs = ''.join([
                c
                for c in vs
                if c >= '0' and c <= '9'
            ])
            if not vs:
                # no digits in component
                raise ValueError('oid %r cannot be normalized' % (oid))
            res.append(vs)
    return '.'.join(res)


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
