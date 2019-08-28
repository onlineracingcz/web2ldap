# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes used on ldap://db.debian.org
"""

from web2ldap.app.schema.syntaxes import DynamicValueSelectList, syntax_registry


class DebianSupplementaryGid(DynamicValueSelectList):
    oid = 'DebianSupplementaryGid-oid'
    desc = 'Debian: sudoUser'
    ldap_url = 'ldap:///_?gid,gid?sub?(objectClass=debianGroup)'

syntax_registry.reg_at(
    DebianSupplementaryGid.oid, [
        '1.3.6.1.4.1.9586.100.4.2.11', # supplementaryGid
    ]
)



# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
