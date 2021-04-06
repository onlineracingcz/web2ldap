# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes used on ldap://db.debian.org
"""

from ..schema.syntaxes import DynamicValueSelectList, syntax_registry
from .opensshlpk import SshPublicKey


syntax_registry.reg_at(
    SshPublicKey.oid, [
        '1.3.6.1.4.1.9586.100.4.2.1',  # sshRSAAuthKey
        '1.3.6.1.4.1.9586.100.4.2.26',  # sshRSAHostKey
    ]
)


class DebianSupplementaryGid(DynamicValueSelectList):
    oid: str = 'DebianSupplementaryGid-oid'
    desc: str = 'Debian: sudoUser'
    ldap_url = 'ldap:///_?gid,gid?sub?(objectClass=debianGroup)'

syntax_registry.reg_at(
    DebianSupplementaryGid.oid, [
        '1.3.6.1.4.1.9586.100.4.2.11', # supplementaryGid
    ]
)



# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
