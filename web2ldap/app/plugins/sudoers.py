# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for sudo-ldap
(see http://www.sudo.ws/sudoers.ldap.man.html)
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import \
    DynamicValueSelectList, \
    NotBefore, \
    NotAfter, \
    syntax_registry


class SudoUserGroup(DynamicValueSelectList):
    oid = 'SudoUserGroup-oid'
    desc = 'United Internet: sudoUser'
    ldap_url = 'ldap:///_?cn,cn?sub?(objectClass=posixGroup)'
    valuePrefix = '%'


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
