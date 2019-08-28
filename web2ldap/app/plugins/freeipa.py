"""
web2ldap plugin classes for FreeIPA
"""

from web2ldap.app.schema.syntaxes import UUID, DNSDomain, syntax_registry
from web2ldap.app.plugins.samba import SambaSID
from web2ldap.app.plugins.opensshlpk import SshPublicKey


syntax_registry.reg_at(
    UUID.oid, [
        '2.16.840.1.113730.3.8.3.1', # ipaUniqueID
    ]
)

syntax_registry.reg_at(
    DNSDomain.oid, [
        '2.16.840.1.113730.3.8.3.4', # fqdn
    ]
)

syntax_registry.reg_at(
    SshPublicKey.oid, [
        '2.16.840.1.113730.3.8.11.31', # ipaSshPubKey
    ]
)

syntax_registry.reg_at(
    SambaSID.oid, [
        '2.16.840.1.113730.3.8.11.2', # ipaNTSecurityIdentifier
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
