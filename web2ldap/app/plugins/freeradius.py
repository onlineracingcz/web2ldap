# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for FreeRADIUS/LDAP schema
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import DynamicDNSelectList, syntax_registry


class RadiusProfileDN(DynamicDNSelectList):
    oid = 'RadiusProfileDN-oid'
    desc = 'DN of a radius profile entry with real data'
    ldap_url = 'ldap:///_??sub?(&(objectClass=radiusprofile)(!(radiusProfileDn=*)))'

syntax_registry.registerAttrType(
    RadiusProfileDN.oid, [
        '1.3.6.1.4.1.3317.4.3.1.49', # radiusProfileDn
    ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
