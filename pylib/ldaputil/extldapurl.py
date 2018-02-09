# -*- coding: utf-8 -*-
"""
ldaputil.ldapurl - extended LDAPUrl class
(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import ldapurl


class ExtendedLDAPUrl(ldapurl.LDAPUrl):
  """
  Class for LDAP URLs passed as query string derived from LDAPUrl
  """
  attr2extype = {
    'who':'bindname',
    'cred':'X-BINDPW',
    'x_startTLS':'x-starttls',
    'saslMech':'x-saslmech',
    'saslAuthzId':'x-saslauthzid',
    'saslRealm':'x-saslrealm',
  }

  def getStartTLSOpt(self,minStartTLSOpt):
    """
    Returns a value indicating whether StartTLS ext.op. shall be used.
    Argument minStartTLSOpt indicates the minimum security level requested.
    0 No
    1 Yes, if possible. Proceed if not possible.
    2 Yes, mandantory. Abort if not possible.
    """
    if not self.extensions:
      return minStartTLSOpt
    try:
      e = self.extensions.get('startTLS',self.extensions['starttls'])
    except KeyError:
      try:
        result = int(self.x_startTLS or '0')
      except ValueError:
        raise ValueError(u'LDAP URL extension x-starttls must be integer 0, 1 or 2.')
    else:
      result = int(e.critical) + int(e.extype.lower()=='starttls')
    return max(result,minStartTLSOpt) # getStartTLSOpt()

  def ldapSearchCommand(self):
    """
    Returns string with OpenLDAP compatible ldapsearch command.
    """
    if self.attrs is None:
      attrs_str = ''
    else:
      attrs_str = ' '.join(self.attrs)
    scope_str = {
      0:'base',
      1:'one',
      2:'sub',
      3:'children',
    }[self.scope]
    if self.saslMech:
      auth_str = '-Y "{saslmech}"'.format(saslmech=self.saslMech)
    elif self.who:
      auth_str = '-x -D "{who}" -W'.format(
        who=self.who or '',
      )
    else:
      auth_str = ''
    if self.x_startTLS:
      tls_str = '-ZZ'
    else:
      tls_str = ''
    if self.extensions:
      # FIX ME! Set extensions
      pass
    ldap_search_command = 'ldapsearch -H "{uri}" {tls} -b "{dn}" -s {scope} {auth} "{filterstr}" {attrs}'.format(
      uri=self.initializeUrl(),
      dn=self.dn,
      scope=scope_str,
      attrs=attrs_str,
      filterstr=self.filterstr or '(objectClass=*)',
      auth=auth_str,
      tls=tls_str,
    )
    return ldap_search_command
