# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for FreeRADIUS/LDAP schema
"""

from web2ldap.app.schema.syntaxes import DynamicDNSelectList, syntax_registry


class RadiusProfileDN(DynamicDNSelectList):
    oid: str = 'RadiusProfileDN-oid'
    desc: str = 'DN of a radius profile entry with real data'
    ldap_url = 'ldap:///_??sub?(&(objectClass=radiusprofile)(!(radiusProfileDn=*)))'

syntax_registry.reg_at(
    RadiusProfileDN.oid, [
        '1.3.6.1.4.1.3317.4.3.1.49', # radiusProfileDn
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
