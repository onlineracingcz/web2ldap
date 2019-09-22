# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for X.500 DSAs
"""

from web2ldap.app.schema.syntaxes import OctetString, syntax_registry


class AccessControlInformation(OctetString):
    oid: str = '1.3.6.1.4.1.1466.115.121.1.1'
    desc: str = 'X.500: Access Control Information (ACI)'


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
