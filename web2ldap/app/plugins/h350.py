# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for H.350 Directory Services (see RFC 3944)
"""

from __future__ import absolute_import


from web2ldap.app.schema.syntaxes import Uri, LDAPUrl, syntax_registry


class CommURI(LDAPUrl):
    oid = 'CommURI-oid'
    desc = 'Labeled URI format to point to the distinguished name of the commUniqueId'

syntax_registry.registerAttrType(
    CommURI.oid, [
        '0.0.8.350.1.1.1.1.1', # commURI
        '0.0.8.350.1.1.2.1.2', # commOwner
    ]
)


syntax_registry.registerAttrType(
    Uri.oid, [
        '0.0.8.350.1.1.6.1.1', # SIPIdentitySIPURI
    ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
