# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for Univention Corporate Server
"""

from __future__ import absolute_import

import bz2

from web2ldap.app.schema.syntaxes import \
    Binary, \
    RFC822Address, \
    DynamicDNSelectList, \
    MultilineText, \
    syntax_registry

from web2ldap.app.plugins.msperson import DateOfBirth


class UniventionPolicyReference(DynamicDNSelectList):
    oid = 'UniventionPolicyReference-oid'
    desc = 'DN of the univentionPolicy entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=univentionPolicy)'

syntax_registry.registerAttrType(
    UniventionPolicyReference.oid, [
        '1.3.6.1.4.1.10176.1000', # univentionPolicyReference
    ]
)


syntax_registry.registerAttrType(
    DateOfBirth.oid, [
        '1.3.6.1.4.1.10176.99', # univentionBirthday
    ]
)


syntax_registry.registerAttrType(
    RFC822Address.oid, [
        '1.3.6.1.4.1.10176.1010.1.1', # mailPrimaryAddress
    ]
)


class UniventionLDAPACLData(Binary, MultilineText):
    oid = 'UniventionLDAPACLData-oid'
    desc = 'bzip2-ed LDAP ACL data in Univention'

    def displayValue(self, valueindex=0, commandbutton=False):
        attr_value = bz2.decompress(self.attrValue)
        attr_value_u = self._ls.uc_decode(attr_value)[0]
        lines = [
            self._form.utf2display(l, tab_identiation='    ')
            for l in self._split_lines(attr_value_u)
        ]
        return '<p>%d bytes <em>BZ2</em> data contains %d chars:</p><pre>%s</pre>' % (
            len(self.attrValue),
            len(attr_value_u),
            '<br>'.join(lines),
        )

syntax_registry.registerAttrType(
    UniventionLDAPACLData.oid, [
        '1.3.6.1.4.1.10176.4202.1.22', # univentionLDAPACLData
    ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
