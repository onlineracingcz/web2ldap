# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for Entrust PKI
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import Binary, syntax_registry

# This overrides the eventually configured OctetString syntax
# and treats these attribute types as not human-readable and
# not editable binary blobs
syntax_registry.reg_at(
    Binary.oid, [
        '1.2.840.113533.7.68.22', # entrustRoamFileEncInfo
        '1.2.840.113533.7.79.0',  # entrustRoamingCAPAB
        '1.2.840.113533.7.68.28', # entrustRoamingEOP
        '1.2.840.113533.7.68.24', # entrustRoamingPAB
        '1.2.840.113533.7.68.27', # entrustRoamingPRV
        '1.2.840.113533.7.68.23', # entrustRoamingProfile
        '1.2.840.113533.7.68.25', # entrustRoamingRecipList
        '1.2.840.113533.7.68.26', # entrustRoamingSLA
        '1.2.840.113533.7.68.30', # entrustPolicyCertificate
        '2.16.840.1.114027.22.4', # entrustAttributeCertificate
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
