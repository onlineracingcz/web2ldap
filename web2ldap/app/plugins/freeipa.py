"""
web2ldap plugin classes for FreeIPA
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import UUID,DNSDomain,syntax_registry
from web2ldap.app.plugins.samba import SambaSID


syntax_registry.registerAttrType(
  UUID.oid,[
    '2.16.840.1.113730.3.8.3.1', # ipaUniqueID
  ]
)


syntax_registry.registerAttrType(
  DNSDomain.oid,[
    '2.16.840.1.113730.3.8.3.4', # fqdn
  ]
)

from web2ldap.app.plugins.opensshlpk import ParamikoSshPublicKey

syntax_registry.registerAttrType(
  ParamikoSshPublicKey.oid,[
    '2.16.840.1.113730.3.8.11.31', # ipaSshPubKey
  ]
)

syntax_registry.registerAttrType(
  SambaSID.oid,[
    '2.16.840.1.113730.3.8.11.2', # ipaNTSecurityIdentifier
  ]
)


# Register all syntax classes in this module
for symbol_name in dir():
  syntax_registry.registerSyntaxClass(eval(symbol_name))
