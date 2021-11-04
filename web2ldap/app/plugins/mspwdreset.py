# -*- coding: ascii -*-
"""
web2ldap plugin classes for msPwdReset*
"""

from ..schema.syntaxes import HashAlgorithmOID, syntax_registry


syntax_registry.reg_at(
    HashAlgorithmOID.oid, [
        '1.3.6.1.4.1.5427.1.389.4.336', # msPwdResetHashAlgorithm
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
