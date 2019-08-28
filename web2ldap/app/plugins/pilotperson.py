# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for pilotPerson

see also RFC1274
"""

from web2ldap.app.schema.syntaxes import SelectList, syntax_registry


class MailPreferenceOption(SelectList):
    oid = 'MailPreferenceOption-oid'
    desc = 'RFC1274: mail preference option syntax'

    attr_value_dict = {
        u'': u'',
        u'0': u'no-list-inclusion',
        u'1': u'any-list-inclusion',
        u'2': u'professional-list-inclusion',
    }

syntax_registry.reg_at(
    MailPreferenceOption.oid, [
        '0.9.2342.19200300.100.1.47', # mailPreferenceOption
    ]
)

# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
