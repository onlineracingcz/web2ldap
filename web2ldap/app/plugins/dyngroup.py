"""
web2ldap plugin classes for attributes defined for so-called dynamic groups
"""

from __future__ import absolute_import

import ldap0
import ldap0.ldapurl

from web2ldap.ldaputil.base import is_dn

from web2ldap.app.schema.syntaxes import LDAPUrl, syntax_registry


class MemberUrl(LDAPUrl):
    oid = 'MemberUrl-oid'
    desc = 'LDAP URL describing search parameters used to lookup group members'
    ldap_url = None

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        LDAPUrl.__init__(self, app, dn, schema, attrType, attrValue, entry)

    def _validate(self, attrValue):
        try:
            ldap_url = ldap0.ldapurl.LDAPUrl(attrValue)
        except ValueError:
            return False
        search_base = ldap_url.dn.decode(self._app.ls.charset)
        if not is_dn(search_base) or ldap_url.hostport:
            return False
        try:
            # Try a dummy base-levelsearch with search base and filter string
            # to provoke server-side errors
            _ = self._app.ls.readEntry(
                search_base,
                attrtype_list=ldap_url.attrs,
                search_filter=ldap_url.filterstr or '(objectClass=*)',
            )
        except ldap0.LDAPError:
            return False
        return True


syntax_registry.reg_at(
    MemberUrl.oid, [
        '2.16.840.1.113730.3.1.198', # memberUrl
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
