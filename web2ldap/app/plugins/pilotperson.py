# -*- coding: ascii -*-
"""
web2ldap plugin classes for attributes defined for pilotPerson

see also RFC1274
"""

from typing import Dict

from ..schema.syntaxes import SelectList, syntax_registry


class MailPreferenceOption(SelectList):
    oid: str = 'MailPreferenceOption-oid'
    desc: str = 'RFC1274: mail preference option syntax'

    attr_value_dict: Dict[str, str] = {
        '': '',
        '0': 'no-list-inclusion',
        '1': 'any-list-inclusion',
        '2': 'professional-list-inclusion',
    }

syntax_registry.reg_at(
    MailPreferenceOption.oid, [
        '0.9.2342.19200300.100.1.47',  # mailPreferenceOption
    ]
)

# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
