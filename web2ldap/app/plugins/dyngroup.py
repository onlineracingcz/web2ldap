"""
web2ldap plugin classes for attributes defined for so-called dynamic groups
"""

from __future__ import absolute_import

import ldap0,ldap0.ldapurl

from web2ldap.ldaputil.base import is_dn

from web2ldap.app.schema.syntaxes import LDAPUrl,syntax_registry


class MemberUrl(LDAPUrl):
  oid = 'MemberUrl-oid'
  desc = 'LDAP URL describing search parameters used to lookup group members'
  ldap_url = None

  def __init__(self, sid, form, ls, dn, schema, attrType, attrValue, entry=None):
    LDAPUrl.__init__(self, sid, form, ls, dn, schema, attrType, attrValue, entry)

  def _validate(self, attrValue):
    try:
      self.lu_obj = ldap0.ldapurl.LDAPUrl(attrValue)
    except ValueError:
      return 0
    else:
      search_base = self.lu_obj.dn.decode(self._ls.charset)
      if not is_dn(search_base) or self.lu_obj.hostport:
        return 0
      else:
        try:
          # Try a dummy base-levelsearch with search base and filter string
          # to provoke server-side errors
          _ = self._ls.readEntry(
            search_base,
            attrtype_list=self.lu_obj.attrs,
            search_filter=self.lu_obj.filterstr or '(objectClass=*)',
          )
        except ldap0.LDAPError:
          return False
        else:
          return True


syntax_registry.registerAttrType(
  MemberUrl.oid, [
    '2.16.840.1.113730.3.1.198', # memberUrl
  ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
