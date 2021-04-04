# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for sudo-ldap
(see http://www.sudo.ws/sudoers.ldap.man.html)
"""

from web2ldap.app.schema.syntaxes import \
    DynamicValueSelectList, \
    NotBefore, \
    NotAfter, \
    syntax_registry


class SudoUserGroup(DynamicValueSelectList):
    oid: str = 'SudoUserGroup-oid'
    desc: str = 'sudo-ldap: sudoUser (group)'
    ldap_url = 'ldap:///_?cn,cn?sub?(objectClass=posixGroup)'
    value_prefix = '%'


syntax_registry.reg_at(
    NotBefore.oid, [
        '1.3.6.1.4.1.15953.9.1.8', # sudoNotBefore
    ]
)


syntax_registry.reg_at(
    NotAfter.oid, [
        '1.3.6.1.4.1.15953.9.1.9', # sudoNotAfter
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
