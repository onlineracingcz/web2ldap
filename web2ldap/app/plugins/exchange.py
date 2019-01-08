# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for MS Exchange 5.5
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import syntax_registry, RFC822Address, Binary
from web2ldap.app.plugins.activedirectory import MsAdGUID

syntax_registry.registerAttrType(
    RFC822Address.oid, [
        '1.2.840.113556.1.2.728', # rfc822Mailbox
        '1.2.840.113556.1.2.729', # mail
    ]
)

# MS AD declares these attributes with OctetString
# syntax but Binary syntax is more suitable
syntax_registry.registerAttrType(
    Binary.oid, [
        '1.2.840.113556.1.4.7000.102.80',    # msExchMailboxSecurityDescriptor
        '1.2.840.113556.1.4.7000.102.50765', # msExchSafeSendersHash
    ]
)

syntax_registry.registerAttrType(
    MsAdGUID.oid, [
        '1.2.840.113556.1.4.7000.102.11058', # msExchMailboxGuid
    ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
