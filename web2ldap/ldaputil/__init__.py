# -*- coding: utf-8 -*-
"""
ldaputil - several LDAP-related utility classes/functions

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import re

import ldap0
import ldap0.sasl
import ldap0.dn
import ldap0.filter

from . import passwd
from . import extldapurl
from . import oidreg


SEARCH_SCOPE_STR = ('base', 'one', 'sub', 'subordinate')

LDAP_OPT_NAMES_DICT = dict([
    (v, k)
    for k, v in vars(ldap0).items()+vars(ldap0.sasl).items()
    if isinstance(v, int)
])

AD_LDAP49_ERROR_CODES = {
    0x525: u'user not found',
    0x52e: u'invalid credentials',
    0x530: u'not permitted to logon at this time',
    0x531: u'not permitted to logon at this workstation',
    0x532: u'password expired',
    0x533: u'account disabled',
    0x701: u'account expired',
    0x773: u'user must reset password',
    0x775: u'user account locked',
}
AD_LDAP49_ERROR_PREFIX = 'AcceptSecurityContext error, data '

attr_type_pattern = u'[\\w;.-]+(;[\\w_-]+)*'
attr_value_pattern = u'(([^,]|\\\\,)+|".*?")'
rdn_pattern = attr_type_pattern + u'[ ]*=[ ]*' + attr_value_pattern


def ietf_oid_str(oid):
    """
    Returns normalized IETF string representation of oid
    """
    vl = oid.split(' ')
    r = []
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
            r.append(vs)
    return '.'.join(r)


def is_dn(s):
    """returns 1 if s is a LDAP DN"""
    assert isinstance(s, unicode), TypeError("Type of argument 's' must be unicode, was %r" % (s))
    return ldap0.dn.is_dn(s.encode('utf-8'))


def explode_rdn_attr(rdn):
    """
    explode_rdn_attr(attr_type_and_value) -> tuple

    This function takes a single attribute type and value pair
    describing a characteristic attribute forming part of a RDN
    (e.g. u'cn=Michael Stroeder') and returns a 2-tuple
    containing the attribute type and the attribute value unescaping
    the attribute value according to RFC 2253 if necessary.
    """
    assert isinstance(rdn, unicode), TypeError("Argument 'rdn' must be unicode, was %r" % (rdn))
    attr_type, attr_value = rdn.split(u'=', 1)
    if attr_value:
        r = []
        start_pos = 0
        i = 0
        attr_value_len = len(attr_value)
        while i < attr_value_len:
            if attr_value[i] == u'\\':
                r.append(attr_value[start_pos:i])
                start_pos = i+1
            i = i+1
        r.append(attr_value[start_pos:i])
        attr_value = u''.join(r)
    return (attr_type, attr_value)


def rdn_dict(dn):
    assert isinstance(dn, unicode), TypeError("Argument 'dn' must be unicode, was %r" % (dn))
    if not dn:
        return {}
    rdn, _ = split_rdn(dn)
    if isinstance(rdn, unicode):
        rdn = rdn.encode('utf-8')
    result = {}
    for i in ldap0.dn.explode_rdn(rdn.strip()):
        attr_type, attr_value = explode_rdn_attr(i.decode('utf-8'))
        if result.has_key(attr_type):
            result[attr_type].append(attr_value)
        else:
            result[attr_type] = [attr_value]
    return result


def explode_dn(dn):
    """
    Unicode wrapper function for ldap0.dn.explode_dn() which returns [] for
    a zero-length DN
    """
    assert isinstance(dn, unicode), TypeError("Argument 'dn' must be unicode, was %r" % (dn))
    if not dn:
        return []
    return [
        rdn.strip().decode('utf-8')
        for rdn in ldap0.dn.explode_dn(dn.encode('utf-8').strip())
    ]


def normalize_dn(dn):
    assert isinstance(dn, unicode), TypeError("Argument 'dn' must be unicode, was %r" % (dn))
    return u','.join(explode_dn(dn))


def matching_dn_components(dn1_components, dn2_components):
    """
    Returns how many levels of two distinguished names
    dn1 and dn2 are matching.
    """
    if not dn1_components or not dn2_components:
        return (0, u'')
    # dn1_cmp has to be shorter than dn2_cmp
    if len(dn1_components) <= len(dn2_components):
        dn1_cmp, dn2_cmp = dn1_components, dn2_components
    else:
        dn1_cmp, dn2_cmp = dn2_components, dn1_components
    i = 1
    dn1_len = len(dn1_cmp)
    while dn1_cmp[-i].lower() == dn2_cmp[-i].lower():
        i = i+1
        if i > dn1_len:
            break
    if i > 1:
        return (i-1, u','.join(dn2_cmp[-i+1:]))
    return (0, u'')


def match_dn(dn1, dn2):
    """
    Returns how much levels of two distinguished names
    dn1 and dn2 are matching.
    """
    return matching_dn_components(explode_dn(dn1), explode_dn(dn2))


def match_dnlist(dn, dnlist):
    """find best matching parent DN of dn in dnlist"""
    dnlist = dnlist or []
    dn_components = explode_dn(dn)
    max_match_level, max_match_name = 0, u''
    for dn_item in dnlist:
        match_level, match_name = matching_dn_components(
            explode_dn(dn_item),
            dn_components
        )
        if match_level > max_match_level:
            max_match_level, max_match_name = match_level, match_name
    return max_match_name


def parent_dn(dn):
    """returns parent-DN of dn"""
    dn_comp = explode_dn(dn)
    if len(dn_comp) > 1:
        return u','.join(dn_comp[1:])
    elif len(dn_comp) == 1:
        return u''
    return None


def parent_dn_list(dn, rootdn=u''):
    """returns a list of parent-DNs of dn"""
    result = []
    dn_components = explode_dn(dn)
    if rootdn:
        max_level = len(dn_components) - len(explode_dn(rootdn))
    else:
        max_level = len(dn_components)
    for i in range(1, max_level):
        result.append(u','.join(dn_components[i:]))
    return result


def split_rdn(dn):
    """returns tuple (RDN,base DN) of dn"""
    if not dn:
        raise ValueError('Empty DN cannot be split.')
    dn_comp = explode_dn(dn)
    return dn_comp[0], u','.join(dn_comp[1:])


def escape_ldap_filter_chars(search_string, charset='utf-8'):
    escape_mode = 0
    if isinstance(search_string, unicode):
        search_string = search_string.encode(charset)
    if isinstance(search_string, bytes):
        try:
            search_string.decode(charset)
        except UnicodeDecodeError:
            escape_mode = 2
    else:
        raise TypeError('Expected search_string as basestring, was %r' % (search_string))
    return ldap0.filter.escape_filter_chars(
        search_string, escape_mode=escape_mode,
    ).decode(charset)


def map_filter_parts(assertion_type, assertion_values, escape_mode=0):
    assert assertion_values, ValueError("'assertion_values' must be non-zero iterator")
    return [
        '(%s=%s)' % (
            assertion_type,
            ldap0.filter.escape_filter_chars(assertion_value, escape_mode=escape_mode),
        )
        for assertion_value in assertion_values
    ]


def compose_filter(operand, filter_parts):
    assert operand in '&|', ValueError("Invalid 'operand': %r" % operand)
    assert filter_parts, ValueError("'filter_parts' must be non-zero iterator")
    if len(filter_parts) == 1:
        res = filter_parts[0]
    elif len(filter_parts) > 1:
        res = '(%s%s)' % (
            operand,
            ''.join(filter_parts),
        )
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
            escape_ldap_filter_chars(dn),
            logdb_entryuuid_attr,
            escape_ldap_filter_chars(entry_uuid),
        )
    else:
        target_filterstr = u'(%s=%s)' % (
            logdb_dn_attr,
            escape_ldap_filter_chars(dn),
        )
    logdb_filterstr = u'(&(objectClass=%s)%s)' % (
        logdb_objectclass,
        target_filterstr,
    )
    return logdb_filterstr
