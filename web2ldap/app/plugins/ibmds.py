# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for IBM Tivoliy Directory Server
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import syntax_registry, OID, DistinguishedName, OctetString

syntax_registry.registerAttrType(
    OID.oid, [
        '1.3.18.0.2.4.2482', # ibm-enabledCapabilities
        '1.3.18.0.2.4.2481', # ibm-supportedCapabilities
        'ibm-supportedacimechanisms',
    ]
)

syntax_registry.registerAttrType(
    DistinguishedName.oid, [
        'ibm-adminid',
    ]
)

syntax_registry.registerAttrType(
    OctetString.oid, [
        '1.3.18.0.2.4.3127', # ibm-slapdCryptoSalt,
        '1.3.18.0.2.4.3116', # ibm-slapdCryptoSync
    ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
