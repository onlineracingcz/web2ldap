# -*- coding: utf-8 -*-
"""
ldaputil.base - basic LDAP functions
(c) by Michael Stroeder <michael@stroeder.com>

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import re,ldap0,ldap0.sasl,ldap0.dn,ldap0.filter

from types import IntType

SEARCH_SCOPE_STR = ['base','one','sub']

SEARCH_SCOPE = {
  # default for empty search scope string
  '':ldap0.SCOPE_BASE,
  # the search scope strings defined in RFC22xx(?)
  'base':ldap0.SCOPE_BASE,
  'one':ldap0.SCOPE_ONELEVEL,
  'sub':ldap0.SCOPE_SUBTREE,
}

try:
  # Check whether constant is present (python-ldap 2.4.15+)
  ldap0.SCOPE_SUBORDINATE
except AttributeError:
  pass
else:
  SEARCH_SCOPE['subordinate'] = ldap0.SCOPE_SUBORDINATE
  SEARCH_SCOPE_STR.append('subordinate')

LDAP_OPT_NAMES_DICT = dict([
  (v,k)
  for k,v in vars(ldap0).items()+vars(ldap0.sasl).items()
  if type(v)==IntType
])

AD_LDAP49_ERROR_CODES = {
  0x525:u'user not found',
  0x52e:u'invalid credentials',
  0x530:u'not permitted to logon at this time',
  0x531:u'not permitted to logon at this workstation',
  0x532:u'password expired',
  0x533:u'account disabled',
  0x701:u'account expired',
  0x773:u'user must reset password',
  0x775:u'user account locked',
}
AD_LDAP49_ERROR_PREFIX = 'AcceptSecurityContext error, data '

attr_type_pattern = ur'[\w;.-]+(;[\w_-]+)*'
attr_value_pattern = ur'(([^,]|\\,)+|".*?")'
rdn_pattern = attr_type_pattern + ur'[ ]*=[ ]*' + attr_value_pattern
dn_pattern   = rdn_pattern + r'([ ]*,[ ]*' + rdn_pattern + r')*[ ]*'

dc_rdn_pattern = ur'(dc|)[ ]*=[ ]*' + attr_value_pattern
dc_dn_pattern   = dc_rdn_pattern + r'([ ]*,[ ]*' + dc_rdn_pattern + r')*[ ]*'

#rdn_regex   = re.compile('^%s$' % rdn_pattern)
dn_regex      = re.compile(u'^%s$' % unicode(dn_pattern))

# Some widely used types
StringType = type('')
UnicodeType = type(u'')


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
        if c>='0' and c<='9'
      ])
      if not vs:
        # no digits in component
        raise ValueError,"oid %s cannot be normalized" % (repr(oid))
      r.append(vs)
  return '.'.join(r)


def is_dn(s):
  """returns 1 if s is a LDAP DN"""
  assert type(s)==UnicodeType, TypeError("Type of argument 's' must be UnicodeType: %s" % repr(s))
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
  assert type(rdn)==UnicodeType, TypeError("Type of argument 'rdn' must be UnicodeType: %s" % repr(rdn))
  attr_type,attr_value = rdn.split(u'=',1)
  if attr_value:
    r = []
    start_pos=0
    i = 0
    attr_value_len=len(attr_value)
    while i<attr_value_len:
      if attr_value[i]==u'\\':
        r.append(attr_value[start_pos:i])
        start_pos=i+1
      i=i+1
    r.append(attr_value[start_pos:i])
    attr_value = u''.join(r)
  return (attr_type,attr_value)


def rdn_dict(dn):
  assert type(dn)==UnicodeType, TypeError("Type of argument 'dn' must be UnicodeType: %s" % repr(dn))
  if not dn:
    return {}
  rdn,_ = SplitRDN(dn)
  if type(rdn)==UnicodeType:
    rdn = rdn.encode('utf-8')
  result = {}
  for i in ldap0.dn.explode_rdn(rdn.strip()):
    attr_type,attr_value = explode_rdn_attr(unicode(i,'utf-8'))
    if result.has_key(attr_type):
      result[attr_type].append(attr_value)
    else:
      result[attr_type]=[attr_value]
  return result


def explode_dn(dn):
  """
  Unicode wrapper function for ldap0.dn.explode_dn() which returns [] for
  a zero-length DN
  """
  assert type(dn)==UnicodeType, TypeError("Type of argument 'dn' must be UnicodeType but was %s" % repr(dn))
  if not dn:
    return []
  assert type(dn)==UnicodeType,'Parameter dn must be Unicode'
  return [ unicode(rdn.strip(),'utf-8') for rdn in ldap0.dn.explode_dn(dn.encode('utf-8').strip()) ]


def normalize_dn(dn):
  assert type(dn)==UnicodeType, TypeError("Type of argument 'dn' must be UnicodeType: %s" % repr(dn))
  return u','.join(explode_dn(dn))


def matching_dn_components(dn1_components,dn2_components):
  """
  Returns how many levels of two distinguished names
  dn1 and dn2 are matching.
  """
  if not dn1_components or not dn2_components:
    return (0,u'')
  # dn1_cmp has to be shorter than dn2_cmp
  if len(dn1_components)<=len(dn2_components):
    dn1_cmp,dn2_cmp = dn1_components,dn2_components
  else:
    dn1_cmp,dn2_cmp = dn2_components,dn1_components
  i = 1 ; dn1_len = len(dn1_cmp)
  while (dn1_cmp[-i].lower()==dn2_cmp[-i].lower()):
    i = i+1
    if i>dn1_len:
      break
  if i>1:
    return (i-1,u','.join(dn2_cmp[-i+1:]))
  return (0,u'')


def match_dn(dn1,dn2):
  """
  Returns how much levels of two distinguished names
  dn1 and dn2 are matching.
  """
  return matching_dn_components(explode_dn(dn1),explode_dn(dn2))


def match_dnlist(dn,dnlist):
  """find best matching parent DN of dn in dnlist"""
  dnlist = dnlist or []
  dn_components = explode_dn(dn)
  max_match_level, max_match_name = 0, u''
  for dn_item in dnlist:
    match_level,match_name = matching_dn_components(
      explode_dn(dn_item),dn_components
    )
    if match_level>max_match_level:
      max_match_level, max_match_name = match_level, match_name
  return max_match_name


def ParentDN(dn):
  """returns parent-DN of dn"""
  dn_comp = explode_dn(dn)
  if len(dn_comp)>1:
    return u','.join(dn_comp[1:])
  elif len(dn_comp)==1:
    return u''
  return None


def ParentDNList(dn,rootdn=u''):
  """returns a list of parent-DNs of dn"""
  result = []
  DNComponentList = explode_dn(dn)
  if rootdn:
    max_level = len(DNComponentList)-len(explode_dn(rootdn))
  else:
    max_level = len(DNComponentList)
  for i in range(1,max_level):
    result.append(u','.join(DNComponentList[i:]))
  return result


def SplitRDN(dn):
  """returns tuple (RDN,base DN) of dn"""
  if not dn:
    raise ValueError('Empty DN cannot be splitted.')
  dn_comp = explode_dn(dn)
  return dn_comp[0], u','.join(dn_comp[1:])


def escape_ldap_filter_chars(search_string,charset='utf-8'):
  escape_mode=0
  if type(search_string)==UnicodeType:
    search_string = search_string.encode(charset)
  elif type(search_string)==StringType:
    try:
      unicode(search_string,charset)
    except UnicodeDecodeError:
      escape_mode=2
  else:
    raise TypeError,'search_string is not UnicodeType or StringType: %s' % (repr(search_string))
  result = unicode(ldap0.filter.escape_filter_chars(search_string,escape_mode=escape_mode),charset)
  return result


def map_filter_parts(assertion_type,assertion_values,escape_mode=0):
  assert assertion_values, ValueError("'assertion_values' must be non-zero iterator")
  return [
    '(%s=%s)' % (
      assertion_type,
      ldap0.filter.escape_filter_chars(assertion_value,escape_mode=escape_mode),
    )
    for assertion_value in assertion_values
  ]


def compose_filter(operand,filter_parts):
  assert operand in '&|', ValueError("Invalid 'operand': %r" % operand)
  assert filter_parts, ValueError("'filter_parts' must be non-zero iterator")
  if len(filter_parts)==1:
    res = filter_parts[0]
  elif len(filter_parts)>1:
    res = '(%s%s)' % (
      operand,
      ''.join(filter_parts),
    )
  return res


def negate_filter(filterstr):
  """
  Returns simple negated filterstr
  """
  if filterstr.startswith(u'(!') and filterstr.endswith(u')'):
    return filterstr[2:-1]
  return u'(!%s)' % filterstr


def logdb_filter(
  logdb_objectclass,
  dn,
  entry_uuid=None,
):
  if logdb_objectclass.startswith(u'audit'):
    logdb_dn_attr = u'reqDN'
    logdb_entryuuid_attr = u'reqEntryUUID'
  elif logdb_objectclass.startswith(u'change'):
    logdb_dn_attr = u'targetDN'
    logdb_entryuuid_attr = u'targetEntryUUID'
  else:
    raise ValueError('Unknown logdb object class %s' % (repr(logdb_objectclass)))
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


def test():
  """Test functions"""

  print '\nTesting function is_dn():'
  ldap_dns = {
    u'o=Michaels':1,
    u'iiii':0,
    u'"cn="Mike"':0,
  }
  for ldap_dn in ldap_dns.keys():
    result_is_dn = is_dn(ldap_dn)
    if result_is_dn !=ldap_dns[ldap_dn]:
      print 'is_dn("%s") returns %d instead of %d.' % (
        ldap_dn,result_is_dn,ldap_dns[ldap_dn]
      )

  print '\nTesting function explode_rdn_attr():'
  ldap_dns = {
    u'cn=Michael Ströder':(u'cn',u'Michael Ströder'),
    u'cn=whois\+\+':(u'cn',u'whois++'),
    u'cn=\#dummy\ ':(u'cn',u'#dummy '),
    u'cn;lang-en-EN=Michael Stroeder':(u'cn;lang-en-EN',u'Michael Stroeder'),
    u'cn=':(u'cn',u''),
  }
  for ldap_dn in ldap_dns.keys():
    result_explode_rdn_attr = explode_rdn_attr(ldap_dn)
    if result_explode_rdn_attr !=ldap_dns[ldap_dn]:
      print 'explode_rdn_attr(%s) returns %s instead of %s.' % (
        repr(ldap_dn),
        repr(result_explode_rdn_attr),repr(ldap_dns[ldap_dn])
      )

  print '\nTesting function match_dn():'
  match_dn_tests = {
    (u'O=MICHAELS',u'o=michaels'):(1,u'O=MICHAELS'),
    (u'CN=MICHAEL STROEDER,O=MICHAELS',u'o=michaels'):(1,u'O=MICHAELS'),
    (u'CN=MICHAEL STROEDER,O=MICHAELS',u''):(0,u''),
    (u'CN=MICHAEL STROEDER,O=MICHAELS',u'     '):(0,u''),
    (u'CN=MICHAEL STRÖDER,O=MICHAELS',u'  cn=Michael Ströder,o=Michaels  '):(2,u'cn=Michael Ströder,o=Michaels'),
    (u'CN=MICHAEL STROEDER,O=MICHAELS',u'mail=michael@stroeder.com,  cn=Michael Stroeder,o=Michaels  '):(2,u'cn=Michael Stroeder,o=Michaels'),
  }
  for dn1,dn2 in match_dn_tests.keys():
    result_match_dn = match_dn(dn1,dn2)
    if result_match_dn[0] !=match_dn_tests[(dn1,dn2)][0] or \
       result_match_dn[1].lower() !=match_dn_tests[(dn1,dn2)][1].lower():
      print 'match_dn(%s,%s) returns:\n%s\ninstead of:\n%s\n' % (
        repr(dn1),repr(dn2),
        repr(result_match_dn),
        repr(match_dn_tests[(dn1,dn2)])
      )


if __name__ == '__main__':
  test()
